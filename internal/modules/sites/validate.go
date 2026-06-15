package sites

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// 严格白名单:任何未列入的字符直接拒绝,绝不进入 nginx 配置模板。
// 防换行注入(\n/\r 会被 nginx 解析为额外指令)、防路径穿越、防 shell 元字符。

// 单个域名标签:RFC1123 子集。整体域名由点分标签组成,允许通配 *.example.com。
var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// upstream 主机:IPv4 或域名(不含通配)。
var hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// PHP fastcgi socket/地址:Unix socket 路径或 host:port。单独校验。
var phpSockRe = regexp.MustCompile(`^/[a-zA-Z0-9._/-]+\.sock$`)

// index 单个文件名:字母数字加 . _ -,无路径分隔符。
var indexFileRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// validDomain 校验单个域名(已小写化)。拒绝换行、空格、超长。
func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	return domainRe.MatchString(d)
}

// validDomains 校验域名列表:非空、每个合法、无重复。
func validDomains(ds []string) error {
	if len(ds) == 0 {
		return fmt.Errorf("at least one domain required")
	}
	if len(ds) > 32 {
		return fmt.Errorf("too many domains (max 32)")
	}
	seen := make(map[string]bool, len(ds))
	for _, d := range ds {
		if !validDomain(d) {
			return fmt.Errorf("invalid domain %q", d)
		}
		if seen[d] {
			return fmt.Errorf("duplicate domain %q", d)
		}
		seen[d] = true
	}
	return nil
}

// validPort 校验 1..65535。
func validPort(p int) bool { return p >= 1 && p <= 65535 }

// validListen 校验监听端口(默认 80;允许 1..65535)。
func validListen(p int) bool { return validPort(p) }

// validUpstream 校验反代目标 scheme://host:port,scheme 限 http/https。
// 返回规范化字符串供模板使用,确保无注入字符。
func validUpstream(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	var scheme, rest string
	switch {
	case strings.HasPrefix(raw, "http://"):
		scheme, rest = "http", strings.TrimPrefix(raw, "http://")
	case strings.HasPrefix(raw, "https://"):
		scheme, rest = "https", strings.TrimPrefix(raw, "https://")
	default:
		return "", fmt.Errorf("upstream must start with http:// or https://")
	}
	host, portStr, ok := strings.Cut(rest, ":")
	if !ok {
		return "", fmt.Errorf("upstream must be scheme://host:port")
	}
	// host:port 后不允许出现路径/查询等任何额外内容。
	if strings.ContainsAny(portStr, "/?# \t") {
		return "", fmt.Errorf("upstream must not contain a path")
	}
	if !hostRe.MatchString(strings.ToLower(host)) || len(host) > 253 {
		return "", fmt.Errorf("invalid upstream host %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || !validPort(port) {
		return "", fmt.Errorf("invalid upstream port %q", portStr)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, strings.ToLower(host), port), nil
}

// validPHPSock 校验 PHP fastcgi 后端:仅允许 unix socket 路径,绝对 .sock。
func validPHPSock(s string) error {
	s = strings.TrimSpace(s)
	if !phpSockRe.MatchString(s) {
		return fmt.Errorf("php fastcgi must be an absolute *.sock unix socket path")
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("php socket path must not contain ..")
	}
	return nil
}

// siteName 由首个域名派生,作为配置文件名/目录名/upstream 名,二次校验防注入。
var siteNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)

func validSiteName(name string) bool {
	return name != "" && len(name) <= 64 && siteNameRe.MatchString(name) && !strings.Contains(name, "..")
}

// safeWebRoot 把相对站点目录拼到 web 基目录下,拒绝穿越到基目录之外。
// 返回清理后的绝对路径。
func safeWebRoot(base, name string) (string, error) {
	if !validSiteName(name) {
		return "", fmt.Errorf("invalid site name %q", name)
	}
	base = filepath.Clean(base)
	joined := filepath.Clean(filepath.Join(base, name))
	if joined != base && !strings.HasPrefix(joined, base+string(filepath.Separator)) {
		return "", fmt.Errorf("resolved web root escapes base directory")
	}
	return joined, nil
}
