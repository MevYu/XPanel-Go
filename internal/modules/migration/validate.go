package migration

import "regexp"

// dbNameRe 限定数据库名:字母数字与 -_,避免注入到 dump/import 命令参数。
var dbNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validDBName(s string) bool { return dbNameRe.MatchString(s) }

// validDBKind 报告数据库类型是否受支持(空表示不带库的纯文件迁移)。
func validDBKind(k string) bool {
	switch k {
	case "", "mysql", "postgres":
		return true
	}
	return false
}
