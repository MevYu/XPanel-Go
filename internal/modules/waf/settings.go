package waf

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Settings 是 waf 模块的可配置路径与开关,可由 admin 经 PUT /settings 修改。
type Settings struct {
	// ConfigDir 是生成的 nginx WAF 配置目录。
	ConfigDir string `json:"config_dir"`
	// HTTPConfName / ServerConfName 是生成的两段配置文件名(置于 ConfigDir 内)。
	HTTPConfName   string `json:"http_conf_name"`
	ServerConfName string `json:"server_conf_name"`
	// NginxConf 是 nginx 主配置路径,供 nginx -t -c 整体校验(空则用 nginx 默认配置)。
	NginxConf string `json:"nginx_conf"`
	// LogPath 是 nginx 访问日志路径,供拦截统计读取。
	LogPath string `json:"log_path"`
}

// DefaultSettings 返回出厂默认设置(对标 aaPanel 的常见布局)。
func DefaultSettings() Settings {
	return Settings{
		ConfigDir:      "/etc/nginx/waf",
		HTTPConfName:   "waf_http.conf",
		ServerConfName: "waf_server.conf",
		NginxConf:      "/etc/nginx/nginx.conf",
		LogPath:        "/var/log/nginx/access.log",
	}
}

// httpConfPath / serverConfPath 拼出两段配置的绝对路径(已由 Validate 保证安全)。
func (s Settings) httpConfPath() string   { return filepath.Join(s.ConfigDir, s.HTTPConfName) }
func (s Settings) serverConfPath() string { return filepath.Join(s.ConfigDir, s.ServerConfName) }

// validAbsPath 校验路径为干净的绝对路径,且不含会破坏 exec/文件操作的危险字符。
// 路径会进 exec.Command 的参数数组(不拼 shell),但仍拒绝换行/NUL/相对逃逸,纵深防御。
func validAbsPath(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	if strings.ContainsAny(p, "\n\r\x00") {
		return false
	}
	// Clean 后须不变:挡掉 "..", 多余分隔符等非规范路径。
	return filepath.Clean(p) == p
}

// validFileName 校验文件名:非空、无路径分隔符、无危险字符(防逃出 ConfigDir)。
func validFileName(n string) bool {
	if n == "" || strings.ContainsAny(n, "/\\\n\r\x00") {
		return false
	}
	return n != "." && n != ".."
}

// Validate 严格校验设置:任何路径/文件名非法即拒,绝不让畸形路径进 exec 或文件写入。
func (s Settings) Validate() error {
	if !validAbsPath(s.ConfigDir) {
		return fmt.Errorf("waf: config_dir must be a clean absolute path")
	}
	if !validFileName(s.HTTPConfName) {
		return fmt.Errorf("waf: http_conf_name must be a bare filename")
	}
	if !validFileName(s.ServerConfName) {
		return fmt.Errorf("waf: server_conf_name must be a bare filename")
	}
	if s.HTTPConfName == s.ServerConfName {
		return fmt.Errorf("waf: http_conf_name and server_conf_name must differ")
	}
	// NginxConf 可空(用 nginx 默认);非空则须合法绝对路径。
	if s.NginxConf != "" && !validAbsPath(s.NginxConf) {
		return fmt.Errorf("waf: nginx_conf must be a clean absolute path")
	}
	if !validAbsPath(s.LogPath) {
		return fmt.Errorf("waf: log_path must be a clean absolute path")
	}
	return nil
}
