package migration

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// dbNameRe 限定数据库名:字母数字与 -_,避免注入到 dump/import 命令参数。
var dbNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validDBName(s string) bool { return dbNameRe.MatchString(s) }

// toolNameRe 限定 DB 工具二进制名为简单可执行名(经 PATH 解析),挡掉 shell 元字符/路径分隔符。
var toolNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// trustedBinDirs 是允许绝对路径指向的受信目录。admin 配置的 DB 工具若给绝对路径,
// 必须落在这些系统目录内,避免把"mysql 客户端"指向 /tmp、家目录等可写位置实现权限洗白。
var trustedBinDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt"}

// validToolPath 报告 DB 工具配置是否安全。空值合法(回落内置默认名)。
// 否则二选一:简单二进制名(toolNameRe,经 PATH 解析);或受信目录下、确实存在的绝对路径。
func validToolPath(v string) bool {
	if v == "" {
		return true
	}
	if !strings.ContainsRune(v, os.PathSeparator) {
		return toolNameRe.MatchString(v)
	}
	if !filepath.IsAbs(v) {
		return false
	}
	clean := filepath.Clean(v)
	dir := filepath.Dir(clean)
	inTrusted := false
	for _, d := range trustedBinDirs {
		if dir == d {
			inTrusted = true
			break
		}
	}
	if !inTrusted {
		return false
	}
	fi, err := os.Stat(clean)
	if err != nil || fi.IsDir() {
		return false
	}
	return true
}

// validToolSettings 校验全部 DB 工具路径配置(导出/导入用),任一非法即返回 false。
func validToolSettings(s Settings) bool {
	return validToolPath(s.MysqlDump) && validToolPath(s.PgDump) &&
		validToolPath(s.MysqlCLI) && validToolPath(s.PsqlCLI)
}

// validDBKind 报告数据库类型是否受支持(空表示不带库的纯文件迁移)。
func validDBKind(k string) bool {
	switch k {
	case "", "mysql", "postgres":
		return true
	}
	return false
}
