package sites

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Settings 是可配置的建站路径与默认值。持久化在 site_settings 表(单行)。
type Settings struct {
	WebRoot   string `json:"web_root"`   // web 根基目录,站点目录建于其下
	ConfDir   string `json:"conf_dir"`   // nginx vhost 配置目录
	LogDir    string `json:"log_dir"`    // 访问/错误日志目录
	PHPSocket string `json:"php_socket"` // PHP 站点默认 fastcgi socket
	BackupDir string `json:"backup_dir"` // 站点备份归档目录
}

// DefaultSettings 是首次运行的默认路径(对标 aaPanel 习惯)。
func DefaultSettings() Settings {
	return Settings{
		WebRoot:   "/www/wwwroot",
		ConfDir:   "/etc/nginx/conf.d",
		LogDir:    "/www/wwwlogs",
		PHPSocket: "/run/php/php-fpm.sock",
		BackupDir: "/www/backup/site",
	}
}

// absDirRe 仅约束设置中的目录:绝对路径、无换行、无 shell 元字符、无 ..
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

// validate 校验全部设置字段。任一非法即返回错误,绝不写入。
func (s Settings) validate() error {
	if err := validAbsDir(s.WebRoot); err != nil {
		return fmt.Errorf("web_root: %w", err)
	}
	if err := validAbsDir(s.ConfDir); err != nil {
		return fmt.Errorf("conf_dir: %w", err)
	}
	if err := validAbsDir(s.LogDir); err != nil {
		return fmt.Errorf("log_dir: %w", err)
	}
	if err := validPHPSock(s.PHPSocket); err != nil {
		return fmt.Errorf("php_socket: %w", err)
	}
	if err := validAbsDir(s.BackupDir); err != nil {
		return fmt.Errorf("backup_dir: %w", err)
	}
	return nil
}
