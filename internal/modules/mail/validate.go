package mail

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// 邮件域名、邮箱地址、别名目标都会作为位置参数写入 postfix/dovecot 的虚拟用户/域/别名
// 配置文件并交给 postmap,必须严格白名单后才允许落盘,挡掉换行注入(污染相邻配置行)、
// shell 元字符与路径逃逸。

// labelRe 是单个 DNS label:首尾字母数字,中间可含连字符,1..63 字符。
var labelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// localPartRe 限定邮箱地址的 local-part:首字符字母数字,其后字母数字加 . _ - +,
// 1..64 字符。比 RFC 5321 严格,排除引号/空白/元字符,保证安全写入虚拟用户文件。
var localPartRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

var (
	// errInvalidDomain 是域名白名单失败的统一错误(用户可见,不含敏感信息)。
	errInvalidDomain = errors.New("invalid mail domain: must be a valid dotted hostname, 1..255 chars")
	// errInvalidEmail 是邮箱地址校验失败的统一错误。
	errInvalidEmail = errors.New("invalid email address: local-part and domain must each be a valid whitelisted token")
	// errInvalidPassword 是密码校验失败的统一错误。
	errInvalidPassword = errors.New("password must be 1..256 chars and contain no control characters")
	// errInvalidQuota 是配额校验失败的统一错误。
	errInvalidQuota = errors.New("quota must be a non-negative integer number of megabytes (0 = unlimited)")
)

// validDomain 报告 s 是否为安全的邮件域名:点分 DNS 主机名,每段合法 label,总长 <=255,
// 无前后导点,至少二级。不接受 IP 字面量(邮件域用域名)。
func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// splitEmail 拆出 local-part 与 domain。要求恰好一个 @ 且两侧非空。
func splitEmail(addr string) (local, domain string, ok bool) {
	i := strings.IndexByte(addr, '@')
	if i <= 0 || i != strings.LastIndexByte(addr, '@') || i == len(addr)-1 {
		return "", "", false
	}
	return addr[:i], addr[i+1:], true
}

// validEmail 报告 addr 是否为安全的完整邮箱地址(local@domain),两段均过白名单。
func validEmail(addr string) bool {
	local, domain, ok := splitEmail(addr)
	if !ok {
		return false
	}
	return localPartRe.MatchString(local) && validDomain(domain)
}

// validAbsPath 校验路径设置:绝对、无控制字符与 shell 元字符、无 ..、cleaned 形式。
// 这些路径会被模块当作落盘/postmap 目标,未约束的 .. 或非 cleaned 形式可越界覆写主机文件。
func validAbsPath(p string) error {
	if p == "" {
		return fmt.Errorf("path must not be empty")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path %q must be absolute", p)
	}
	if strings.ContainsAny(p, "\n\r\t ;{}*?$`\\\"'") {
		return fmt.Errorf("path %q contains forbidden characters", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("path %q must not contain ..", p)
	}
	if filepath.Clean(p) != p {
		return fmt.Errorf("path %q must be in cleaned form", p)
	}
	return nil
}

// validPassword 报告口令长度合规且不含控制字符(挡 NUL/换行注入 dovecot 用户库)。
// 口令本身经 stdin 交给 doveadm pw 哈希,但仍拒绝控制字符以防纵深失效。
func validPassword(p string) bool {
	if len(p) == 0 || len(p) > 256 {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
