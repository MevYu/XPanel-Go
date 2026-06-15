package backup

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

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

// toolNameRe 限定 dump 工具的"裸二进制名"(PATH 查找):字母数字与 . _ -,1..64。
var toolNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// validToolPath 报告 mysqldump/pg_dump 路径是否安全:空(回落默认)、裸二进制名,
// 或干净的绝对路径。这些值进 exec.Command 的 argv[0],必须挡住注入/相对穿越。
func validToolPath(p string) bool {
	if p == "" {
		return true
	}
	if strings.ContainsAny(p, "\n\r\x00") {
		return false
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p) == p
	}
	// 非绝对路径只允许裸二进制名(无分隔符),交给 PATH 解析。
	return toolNameRe.MatchString(p)
}

// regionRe 限定 region:字母数字与 -_,云厂商 region 命名足够。空值允许。
var regionRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validRegion(s string) bool { return s == "" || regionRe.MatchString(s) }

// validEndpoint 报告 endpoint 是否合法:空允许;否则须为 http/https 且带主机的 URL。
func validEndpoint(s string) bool {
	if s == "" {
		return true
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	return true
}

// validateSettings 校验可执行工具路径(进 exec 的字段)。空值回落默认,合法。
func validateSettings(s Settings) error {
	if !validToolPath(s.MysqlDump) {
		return fmt.Errorf("mysqldump must be a bare binary name or a clean absolute path")
	}
	if !validToolPath(s.PgDump) {
		return fmt.Errorf("pgdump must be a bare binary name or a clean absolute path")
	}
	return nil
}

// validateRemote 校验远端的 endpoint/region(其余字段另有白名单/约束)。
func validateRemote(r Remote) error {
	if !validEndpoint(r.Endpoint) {
		return fmt.Errorf("endpoint must be a valid http(s) URL")
	}
	if !validRegion(r.Region) {
		return fmt.Errorf("region contains invalid characters")
	}
	return nil
}
