package ftp

import (
	"errors"
	"path/filepath"
	"regexp"
	"strconv"
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
	// errInvalidID 是 uid/gid 校验失败的统一错误。
	errInvalidID = errors.New("virtual_uid/virtual_gid must be a non-privileged numeric id (>=1000) or a service account name")
	// errInvalidQuota 是配额校验失败的统一错误。
	errInvalidQuota = errors.New("quota_mb must be an integer in 0..1048576 (MB); 0 = unlimited")
)

// maxQuotaMB 是允许的最大存储配额(MB),约 1 TB。
const maxQuotaMB = 1048576

// validQuota 报告配额(MB)是否在合法范围 0..maxQuotaMB(0=不限)。
func validQuota(mb int) bool { return mb >= 0 && mb <= maxQuotaMB }

// minNonPrivilegedID 是允许映射的最小数字 uid/gid。低于此值(尤其 0=root)拒绝,
// 避免把 FTP 虚拟用户映射到 root 或系统保留账户而越权。
const minNonPrivilegedID = 1000

// serviceAccountRe 限定按"名字"指定的服务账户:首字符字母,其后字母数字加 . _ -。
// 解析为具体 uid 留给后端(getpwnam),此处仅挡注入字符;纯数字另走数字校验。
var serviceAccountRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,31}$`)

// validVirtualID 报告 uid/gid 设置值是否安全:
//   - 纯数字:必须 >= minNonPrivilegedID(挡 root/系统账户)。
//   - 非数字:必须是合法服务账户名(交后端解析,绝不含 shell/路径字符)。
//
// 空串由调用方(overlay)用默认值兜底,不在此判定。
func validVirtualID(s string) bool {
	if s == "" {
		return false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n >= minNonPrivilegedID
	}
	return serviceAccountRe.MatchString(s)
}

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
