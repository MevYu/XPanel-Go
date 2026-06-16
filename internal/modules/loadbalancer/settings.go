package loadbalancer

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Settings 是可配置的 nginx upstream 配置目录。持久化在 lb_settings 表(单行)。
type Settings struct {
	ConfDir string `json:"conf_dir"` // nginx upstream/proxy 配置目录
}

// DefaultSettings 是首次运行的默认路径。
func DefaultSettings() Settings {
	return Settings{ConfDir: "/etc/nginx/conf.d"}
}

// validAbsDir 约束设置目录:绝对路径、无换行、无 shell 元字符、无 ..、已清理。
func validAbsDir(p string) error {
	p = strings.TrimSpace(p)
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

func (s Settings) validate() error {
	if err := validAbsDir(s.ConfDir); err != nil {
		return fmt.Errorf("conf_dir: %w", err)
	}
	return nil
}
