package php

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Settings 是 php 模块的可配置路径,可由 admin 经 PUT /settings 修改。
// 对标 aaPanel 的 /www/server/php 布局:每个版本一个子目录,版本号即目录名。
type Settings struct {
	// InstallBase 是 PHP 多版本安装基目录,每个版本一个子目录(目录名为版本号)。
	InstallBase string `json:"install_base"`
	// FpmConfDir 是 php-fpm 配置目录(用于扩展 ini 的启用/禁用文件落盘)。
	FpmConfDir string `json:"fpm_conf_dir"`
	// FpmSockDir 是 php-fpm 监听 sock 所在目录。
	FpmSockDir string `json:"fpm_sock_dir"`
	// FpmUnitTemplate 是 php-fpm systemd 单元名模板,%s 处替换为版本号(如 "php%s-fpm")。
	FpmUnitTemplate string `json:"fpm_unit_template"`
	// DebianRoot 是 Debian/Ubuntu 的 PHP 多版本配置根(每版本一子目录,如 /etc/php/8.3/fpm/php.ini)。
	DebianRoot string `json:"debian_root"`
	// DebianBinDir 是 Debian/Ubuntu 的 php<ver> CLI 二进制目录(如 /usr/bin/php8.3)。
	DebianBinDir string `json:"debian_bin_dir"`
	// ProcRoot 是 procfs 挂载点;无 systemd 时扫此处的 */comm 退化探测 fpm 是否运行。
	ProcRoot string `json:"proc_root"`
}

// DefaultSettings 返回出厂默认设置(对标 aaPanel 的常见布局 + Debian/Ubuntu 标准路径)。
func DefaultSettings() Settings {
	return Settings{
		InstallBase:     "/www/server/php",
		FpmConfDir:      "/www/server/php",
		FpmSockDir:      "/tmp",
		FpmUnitTemplate: "php-fpm-%s",
		DebianRoot:      "/etc/php",
		DebianBinDir:    "/usr/bin",
		ProcRoot:        "/proc",
	}
}

// fillDebianDefaults 把空的 Debian/proc 路径补成出厂默认。旧设置记录(本特性之前写入)
// 这些字段为空,读出后补默认,保证按版本解析路径时永远有合法的 Debian 根。
func (s *Settings) fillDebianDefaults() {
	d := DefaultSettings()
	if s.DebianRoot == "" {
		s.DebianRoot = d.DebianRoot
	}
	if s.DebianBinDir == "" {
		s.DebianBinDir = d.DebianBinDir
	}
	if s.ProcRoot == "" {
		s.ProcRoot = d.ProcRoot
	}
}

// versionDir 返回某版本的安装子目录绝对路径。version 须已经 ValidVersion 校验。
func (s Settings) versionDir(version string) string {
	return filepath.Join(s.InstallBase, version)
}

// phpBin 返回某版本的 php CLI 可执行路径(<base>/<version>/bin/php)。
func (s Settings) phpBin(version string) string {
	return filepath.Join(s.versionDir(version), "bin", "php")
}

// fpmConfDir 返回某版本的 php-fpm 配置目录(<fpmConfDir>/<version>/etc/php-fpm.d)。
func (s Settings) fpmConfDir(version string) string {
	return filepath.Join(s.FpmConfDir, version, "etc", "php-fpm.d")
}

// iniPath 返回某版本的 php.ini 路径(<base>/<version>/etc/php.ini)。
func (s Settings) iniPath(version string) string {
	return filepath.Join(s.versionDir(version), "etc", "php.ini")
}

// extConfDir 返回某版本的扩展 ini 目录(<base>/<version>/etc/php.d)。
// 启用/禁用扩展通过在此目录写/删 <ext>.ini 实现。
func (s Settings) extConfDir(version string) string {
	return filepath.Join(s.versionDir(version), "etc", "php.d")
}

// fpmPoolConf 返回某版本的 fpm www pool 配置路径(<base>/<version>/etc/php-fpm.d/www.conf)。
func (s Settings) fpmPoolConf(version string) string {
	return filepath.Join(s.versionDir(version), "etc", "php-fpm.d", "www.conf")
}

// slowLogPath 返回某版本的 fpm 慢日志路径(<base>/<version>/var/log/slow.log)。
func (s Settings) slowLogPath(version string) string {
	return filepath.Join(s.versionDir(version), "var", "log", "slow.log")
}

// errorLogPath 返回某版本的 php 错误日志路径(<base>/<version>/var/log/php-fpm.log)。
func (s Settings) errorLogPath(version string) string {
	return filepath.Join(s.versionDir(version), "var", "log", "php-fpm.log")
}

// fpmUnit 返回某版本的 php-fpm systemd 单元名(模板替换版本号)。
func (s Settings) fpmUnit(version string) string {
	if strings.Contains(s.FpmUnitTemplate, "%s") {
		return fmt.Sprintf(s.FpmUnitTemplate, version)
	}
	return s.FpmUnitTemplate
}

// validAbsPath 校验路径为干净的绝对路径,且不含会破坏 exec/文件操作的危险字符。
func validAbsPath(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	if strings.ContainsAny(p, "\n\r\x00") {
		return false
	}
	return filepath.Clean(p) == p
}

// 单元名模板白名单:字母数字 . _ - @ %,长度受限。须含一处 %s,且替换后仍为合法单元名。
var unitTemplateForbidden = "\n\r\x00 ;{}\"'\\$#/"

// Validate 严格校验设置:任何路径/模板非法即拒,绝不让畸形值进 exec 或文件写入。
func (s Settings) Validate() error {
	if !validAbsPath(s.InstallBase) {
		return fmt.Errorf("php: install_base must be a clean absolute path")
	}
	if !validAbsPath(s.FpmConfDir) {
		return fmt.Errorf("php: fpm_conf_dir must be a clean absolute path")
	}
	if !validAbsPath(s.FpmSockDir) {
		return fmt.Errorf("php: fpm_sock_dir must be a clean absolute path")
	}
	if s.FpmUnitTemplate == "" || strings.ContainsAny(s.FpmUnitTemplate, unitTemplateForbidden) {
		return fmt.Errorf("php: fpm_unit_template contains forbidden characters")
	}
	if !strings.Contains(s.FpmUnitTemplate, "%s") {
		return fmt.Errorf("php: fpm_unit_template must contain %%s placeholder")
	}
	if !validAbsPath(s.DebianRoot) {
		return fmt.Errorf("php: debian_root must be a clean absolute path")
	}
	if !validAbsPath(s.DebianBinDir) {
		return fmt.Errorf("php: debian_bin_dir must be a clean absolute path")
	}
	if !validAbsPath(s.ProcRoot) {
		return fmt.Errorf("php: proc_root must be a clean absolute path")
	}
	return nil
}
