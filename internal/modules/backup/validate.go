package backup

import "regexp"

// remoteNameRe 限定 rclone remote 名:字母数字与 -_,1-64 字符。
// 该名字会进 exec.Command 参数(rclone "name:bucket/...")与目录名,严格白名单。
var remoteNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validRemoteName(s string) bool { return remoteNameRe.MatchString(s) }

// validTargetKind 报告备份目标类型是否受支持。
func validTargetKind(k string) bool {
	switch k {
	case "path", "mysql", "postgres":
		return true
	}
	return false
}

// dbNameRe 限定数据库名:字母数字与 -_,避免注入到 dump 命令参数。
var dbNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validDBName(s string) bool { return dbNameRe.MatchString(s) }
