package database

import (
	"errors"
	"regexp"
	"strings"
)

// SQL 标识符(库名/用户名)无法参数化:必须严格白名单后再按各自方言引用。
// 任何不匹配白名单的输入一律拒绝,绝不进 SQL 文本。
var identRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// errInvalidIdent 是标识符校验失败的统一错误(用户可见,不含敏感信息)。
var errInvalidIdent = errors.New("invalid identifier: must match ^[A-Za-z0-9_]{1,64}$")

// validIdent 报告 s 是否为安全标识符(库名/用户名)。
func validIdent(s string) bool { return identRe.MatchString(s) }

// MySQL 账户主机部分:localhost、%、或 IPv4(可带通配 %)、点分主机名。
// 进 SQL 时仍作字符串字面量转义,这里白名单是纵深防御。
var hostRe = regexp.MustCompile(`^[A-Za-z0-9_.%:-]{1,255}$`)

// errInvalidHost 是主机校验失败错误。
var errInvalidHost = errors.New("invalid host: must match ^[A-Za-z0-9_.%:-]{1,255}$")

// validHost 报告 s 是否为安全的 MySQL 账户主机部分。空串视为非法(调用方应默认 %)。
func validHost(s string) bool { return s != "" && hostRe.MatchString(s) }

// charset/collation 名:字母数字下划线(utf8mb4、utf8mb4_unicode_ci、UTF8 等)。
var charsetRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// validCharset 报告 s 是否为安全的字符集/排序规则/编码名。
func validCharset(s string) bool { return charsetRe.MatchString(s) }

// quoteMySQL 反引号引用一个已通过白名单的 MySQL 标识符。
// 白名单已排除反引号,这里仍按方言正确转义以防纵深失效。
func quoteMySQL(ident string) (string, error) {
	if !validIdent(ident) {
		return "", errInvalidIdent
	}
	return "`" + strings.ReplaceAll(ident, "`", "``") + "`", nil
}

// quotePG 双引号引用一个已通过白名单的 PostgreSQL 标识符。
func quotePG(ident string) (string, error) {
	if !validIdent(ident) {
		return "", errInvalidIdent
	}
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`, nil
}
