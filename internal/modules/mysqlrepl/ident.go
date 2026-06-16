package mysqlrepl

import (
	"errors"
	"regexp"
	"strings"
)

// SQL 标识符(用户名/库名)无法参数化:必须严格白名单后再按 MySQL 反引号引用。
// 任何不匹配白名单的输入一律拒绝,绝不进 SQL 文本。
var identRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// errInvalidIdent 是标识符校验失败的统一错误(用户可见,不含敏感信息)。
var errInvalidIdent = errors.New("invalid identifier: must match ^[A-Za-z0-9_]{1,64}$")

// validIdent 报告 s 是否为安全标识符(库名/用户名)。
func validIdent(s string) bool { return identRe.MatchString(s) }

// quoteMySQL 反引号引用一个已通过白名单的 MySQL 标识符。
// 白名单已排除反引号,这里仍按方言正确转义以防纵深失效。
func quoteMySQL(ident string) (string, error) {
	if !validIdent(ident) {
		return "", errInvalidIdent
	}
	return "`" + strings.ReplaceAll(ident, "`", "``") + "`", nil
}

// quoteStringLiteral 把一个值转义为 SQL 单引号字符串字面量(用于口令、host 等无法参数化的位置)。
// 单引号翻倍、反斜杠翻倍(MySQL 默认 NO_BACKSLASH_ESCAPES 关闭,反斜杠是转义符)。
func quoteStringLiteral(v string) string {
	out := make([]byte, 0, len(v)+2)
	out = append(out, '\'')
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\'':
			out = append(out, '\'', '\'')
		case '\\':
			out = append(out, '\\', '\\')
		default:
			out = append(out, v[i])
		}
	}
	out = append(out, '\'')
	return string(out)
}
