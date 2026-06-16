package sites

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// 扩展白名单校验:php 版本、防盗链扩展名、referer、basic 用户名、location 路径、
// 重定向目标与状态码、原始 nginx 片段。全部拒绝换行/元字符,绝不进配置。

// validPHPVersion 校验 PHP 版本号,形如 "8.2"(主.次)。不容忍任何空白字符。
func validPHPVersion(v string) bool {
	major, minor, ok := strings.Cut(v, ".")
	if !ok || major == "" || minor == "" {
		return false
	}
	if !isDigits(major) || !isDigits(minor) || len(major) > 2 || len(minor) > 2 {
		return false
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// validExtension 校验防盗链扩展名:字母数字加单个内部点(如 tar.gz),无前导点。
func validExtension(e string) bool {
	if e == "" || len(e) > 16 {
		return false
	}
	if strings.HasPrefix(e, ".") || strings.HasSuffix(e, ".") || strings.Contains(e, "..") {
		return false
	}
	for _, c := range e {
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '.' {
			return false
		}
	}
	return true
}

// validReferer 校验 valid_referers 主机项:域名/通配域名,或哨兵 none/blocked。
func validReferer(r string) bool {
	if r == "none" || r == "blocked" {
		return true
	}
	return validDomain(strings.ToLower(r))
}

// validBasicUsername 校验 auth_basic 用户名:无冒号(htpasswd 分隔符)、无空白/元字符。
func validBasicUsername(u string) bool {
	if u == "" || len(u) > 64 {
		return false
	}
	if strings.Contains(u, "..") {
		return false
	}
	for _, c := range u {
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// validLocationPath 校验 location 前缀路径:绝对、无空白/元字符/穿越。
func validLocationPath(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") {
		return fmt.Errorf("location path %q must start with /", p)
	}
	if len(p) > 256 {
		return fmt.Errorf("location path too long")
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("location path %q must not contain ..", p)
	}
	if strings.ContainsAny(p, " \t\n\r;{}$*?\"'`\\") {
		return fmt.Errorf("location path %q contains forbidden characters", p)
	}
	return nil
}

// validRedirectTarget 校验重定向目标:绝对 http(s) URL 或本地绝对路径,
// 拒绝 javascript:、协议相对 //、换行与元字符。
func validRedirectTarget(t string) error {
	t = strings.TrimSpace(t)
	if t == "" || len(t) > 2048 {
		return fmt.Errorf("redirect target empty or too long")
	}
	if strings.ContainsAny(t, " \t\n\r;{}\"'`\\<>") {
		return fmt.Errorf("redirect target %q contains forbidden characters", t)
	}
	switch {
	case strings.HasPrefix(t, "https://"), strings.HasPrefix(t, "http://"):
		return nil
	case strings.HasPrefix(t, "//"):
		return fmt.Errorf("protocol-relative redirect target not allowed")
	case strings.HasPrefix(t, "/"):
		return nil
	default:
		return fmt.Errorf("redirect target must be http(s) URL or absolute path")
	}
}

// validRedirectCode 仅允许 301/302。
func validRedirectCode(c int) bool { return c == 301 || c == 302 }

// validNginxFragment 是原始片段(rewrite/custom)的注入兜底:拒绝 NUL 与裸 CR。
// nginx 指令以分号/花括号分隔,这些是合法配置语法,故只能拦控制字符,真正把关靠 nginx -t。
func validNginxFragment(s string) error {
	if len(s) > 64*1024 {
		return fmt.Errorf("config fragment too large")
	}
	if strings.ContainsRune(s, '\x00') {
		return fmt.Errorf("config fragment contains NUL byte")
	}
	// 裸 \r(非 \r\n 的一部分)在 nginx 配置中无意义,通常是注入痕迹。
	if strings.Contains(strings.ReplaceAll(s, "\r\n", "\n"), "\r") {
		return fmt.Errorf("config fragment contains bare carriage return")
	}
	return nil
}

// validCertPath 校验 TLS 证书/私钥文件路径:绝对、无穿越/元字符。
func validCertPath(p string) error {
	if p == "" {
		return fmt.Errorf("path must not be empty")
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must be absolute", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("path %q must not contain ..", p)
	}
	if strings.ContainsAny(p, " \t\n\r;{}$*?\"'`\\") {
		return fmt.Errorf("path %q contains forbidden characters", p)
	}
	return nil
}

// proxyHeaderNameRe 限定 proxy_set_header 头名:HTTP token 子集(字母数字与连字符)。
var proxyHeaderNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// validProxyHeaderName 校验 proxy_set_header 头名。
func validProxyHeaderName(s string) bool { return proxyHeaderNameRe.MatchString(s) }

// validProxyHeaderValue 校验头值:非空、限长、无换行与 nginx 元字符。
func validProxyHeaderValue(s string) error {
	if s == "" || len(s) > 1024 {
		return fmt.Errorf("proxy header value empty or too long")
	}
	if strings.ContainsAny(s, "\n\r;{}") {
		return fmt.Errorf("proxy header value contains forbidden characters")
	}
	return nil
}

// validSendHost 校验 proxy_set_header Host 的值:空、$host、$proxy_host 或合法域名。
func validSendHost(s string) bool {
	switch s {
	case "", "$host", "$proxy_host":
		return true
	}
	return validDomain(strings.ToLower(s))
}

// safeAbsUnder 校验一个绝对路径必须落在 base 目录内。
// 拒绝相对路径、.. 穿越、空白/元字符。返回 filepath.Clean 后的路径。
func safeAbsUnder(base, p string) (string, error) {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path %q must be absolute", p)
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("path %q must not contain ..", p)
	}
	if strings.ContainsAny(p, " \t\n\r;{}$*?\"'`\\") {
		return "", fmt.Errorf("path %q contains forbidden characters", p)
	}
	base = filepath.Clean(base)
	cleaned := filepath.Clean(p)
	if cleaned != base && !strings.HasPrefix(cleaned, base+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes web root", p)
	}
	return cleaned, nil
}

// validDomainBinding 校验一条域名+端口绑定。port 0 视为默认(80)。
func validDomainBinding(d Domain) error {
	if !validDomain(strings.ToLower(strings.TrimSpace(d.Domain))) {
		return fmt.Errorf("invalid domain %q", d.Domain)
	}
	if d.Port != 0 && !validPort(d.Port) {
		return fmt.Errorf("invalid port %d for domain %q", d.Port, d.Domain)
	}
	return nil
}
