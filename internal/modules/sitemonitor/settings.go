package sitemonitor

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Settings 是网站监控的可配置项,可由 admin 经 PUT /settings 修改。
type Settings struct {
	// LogRoot 是允许读取日志的根目录;所有访问日志路径都被 SafeJoin 限定在此子树内,挡路径穿越。
	LogRoot string `json:"log_root"`
	// AccessLog 是默认 nginx 访问日志路径(可为 LogRoot 下的相对路径或其子树内的绝对路径)。
	AccessLog string `json:"access_log"`
	// MaxLines 是单次分析最多读取的尾部行数;0 用 DefaultMaxLines,防大日志撑爆内存。
	MaxLines int `json:"max_lines"`
}

// DefaultMaxLines 是默认尾部读取上限。
const DefaultMaxLines = 200000

// DefaultSettings 返回出厂默认(对标 aaPanel 的 /www/wwwlogs 与发行版默认 nginx 路径)。
func DefaultSettings() Settings {
	return Settings{
		LogRoot:   "/www/wwwlogs",
		AccessLog: "/www/wwwlogs/access.log",
		MaxLines:  DefaultMaxLines,
	}
}

// effectiveMaxLines 返回生效的行上限(0 → 默认)。
func (s Settings) effectiveMaxLines() int {
	if s.MaxLines <= 0 {
		return DefaultMaxLines
	}
	return s.MaxLines
}

// validAbsPath 校验路径为干净的绝对路径,且不含会破坏文件操作的危险字符。
func validAbsPath(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	if strings.ContainsAny(p, "\n\r\x00") {
		return false
	}
	return filepath.Clean(p) == p
}

// Validate 严格校验设置:任何非法路径即拒。
func (s Settings) Validate() error {
	if !validAbsPath(s.LogRoot) {
		return fmt.Errorf("sitemonitor: log_root must be a clean absolute path")
	}
	if s.AccessLog == "" || strings.ContainsAny(s.AccessLog, "\n\r\x00") {
		return fmt.Errorf("sitemonitor: access_log must be set and free of control chars")
	}
	if s.MaxLines < 0 {
		return fmt.Errorf("sitemonitor: max_lines must be non-negative")
	}
	return nil
}
