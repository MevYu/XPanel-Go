package ftp

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

// FTP 用户名与家目录无法参数化进 exec 参数的语义层(pure-pw 把它们当位置参数),
// 必须严格白名单后才允许传给外部命令,挡掉注入与路径逃逸。

// userRe 限定 FTP 虚拟用户名:首字符字母数字,其后字母数字加 . _ -,1..32 字符。
// 排除路径分隔符、空白、shell 元字符,保证安全传给 pure-pw。
var userRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

var (
	// errInvalidUser 是用户名白名单失败的统一错误(用户可见,不含敏感信息)。
	errInvalidUser = errors.New("invalid ftp username: must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
	// errInvalidHome 是家目录校验失败的统一错误。
	errInvalidHome = errors.New("invalid home directory: must be an absolute path under the configured base, no '..'")
	// errInvalidPassword 是密码校验失败的统一错误。
	errInvalidPassword = errors.New("password must be 1..256 chars and contain no control characters")
)

// validUser 报告 s 是否为安全的 FTP 用户名。
func validUser(s string) bool { return userRe.MatchString(s) }

// validPassword 报告口令长度合规且不含控制字符(挡 NUL/换行注入 pure-pw 交互)。
// 口令本身经 stdin 传入而不进 exec 参数,但仍拒绝控制字符以防纵深失效。
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

// resolveHome 校验并归一化家目录:必须是 base 子树内的绝对路径,无 ".." 逃逸。
// 返回 Clean 后的绝对路径(供创建账户时传给 pure-pw -d)。
//
// 纯词法判定(家目录尚未创建,base 由 admin 配置可信,不解析符号链接):
//  1. 必须绝对路径(pure-ftpd 的 chroot 家目录)。
//  2. Clean 后等于 base 或以 base+"/" 为前缀(挡 "../"、绝对逃逸)。
func resolveHome(base, home string) (string, error) {
	base = filepath.Clean(base)
	if !filepath.IsAbs(home) {
		return "", errInvalidHome
	}
	clean := filepath.Clean(home)
	if clean != base && !strings.HasPrefix(clean, base+string(filepath.Separator)) {
		return "", errInvalidHome
	}
	return clean, nil
}
