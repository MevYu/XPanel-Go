package php

import (
	"os"
	"path/filepath"
)

// versionPaths 是某个已安装 PHP 版本的解析后路径集,屏蔽 aaPanel 与 Debian 两种布局差异,
// 各 handler 统一据此读写 ini/fpm/日志。version 须已 ValidVersion 校验,所有路径由本包推导,
// 无外部注入字符,故不存在路径逃逸。
type versionPaths struct {
	Version  string
	Source   string // "aapanel" | "debian"
	PhpBin   string // php CLI 可执行路径
	IniPath  string // php.ini
	ExtDir   string // 扩展 ini 目录(写/删 <ext>.ini 启停扩展)
	PoolConf string // fpm pool www.conf
	SlowLog  string // fpm 慢日志
	ErrorLog string // fpm 错误日志
	FpmUnit  string // php-fpm systemd 单元名
}

// resolveVersion 解析某版本的路径集:优先 aaPanel 布局(其版本子目录存在即认定),
// 否则回落 Debian 安装。版本冲突时 aaPanel 优先(与 /versions 合并策略一致)。
// 两边都查不到返回 ok=false,调用方据此回 404。version 须已 ValidVersion 校验。
func (s Settings) resolveVersion(version string) (versionPaths, bool) {
	if dirExists(s.versionDir(version)) {
		return s.aapanelPaths(version), true
	}
	for _, in := range detectDebianInstalls(s.DebianRoot, s.DebianBinDir) {
		if in.Version == version {
			return debianPaths(in), true
		}
	}
	return versionPaths{}, false
}

// aapanelPaths 用 aaPanel 布局的 Settings 路径方法填充路径集。
func (s Settings) aapanelPaths(version string) versionPaths {
	return versionPaths{
		Version:  version,
		Source:   sourceAapanel,
		PhpBin:   s.phpBin(version),
		IniPath:  s.iniPath(version),
		ExtDir:   s.extConfDir(version),
		PoolConf: s.fpmPoolConf(version),
		SlowLog:  s.slowLogPath(version),
		ErrorLog: s.errorLogPath(version),
		FpmUnit:  s.fpmUnit(version),
	}
}

// debianPaths 把一个 Debian 安装映射为统一路径集。Debian/Ubuntu 的 fpm 慢日志/错误日志
// 默认落 /var/log/php<ver>-fpm.log 与 /var/log/php<ver>-fpm.slow.log。
func debianPaths(in debianInstall) versionPaths {
	return versionPaths{
		Version:  in.Version,
		Source:   sourceDebian,
		PhpBin:   in.PhpBin,
		IniPath:  in.IniPath,
		ExtDir:   in.confDir(),
		PoolConf: in.PoolConf,
		SlowLog:  filepath.Join("/var/log", "php"+in.Version+"-fpm.slow.log"),
		ErrorLog: filepath.Join("/var/log", "php"+in.Version+"-fpm.log"),
		FpmUnit:  in.FpmUnit,
	}
}

const (
	sourceAapanel = "aapanel"
	sourceDebian  = "debian"
)

// dirExists 报告 path 是已存在的目录。
func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
