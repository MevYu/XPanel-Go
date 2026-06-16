package php

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// debianInstall 描述一个 Debian/Ubuntu 风格的 PHP 安装(路径与 aaPanel 布局不同,
// 故单独建模而非复用 Settings 的版本子目录模板)。
type debianInstall struct {
	Version  string
	PhpBin   string // <binDir>/php<ver>,如 /usr/bin/php8.3
	IniPath  string // <root>/<ver>/fpm/php.ini
	PoolConf string // <root>/<ver>/fpm/pool.d/www.conf
	FpmUnit  string // php<ver>-fpm
	HasFpm   bool   // <root>/<ver>/fpm 目录存在(否则为 CLI-only 安装)
}

// confDir 返回该安装放 ext ini 的目录(<root>/<ver>/fpm/conf.d)。
func (d debianInstall) confDir() string {
	return filepath.Join(filepath.Dir(d.IniPath), "conf.d")
}

// detectDebianInstalls 扫描 Debian/Ubuntu 的 PHP 配置根(root,通常 /etc/php),
// 每个子目录名为合法版本号即视为一个安装,推导 ini/pool/单元名/CLI 二进制路径。
// root 不存在 / 不可读时返回 nil(环境无 Debian 风格 PHP 视为正常)。
// binDir 为 php<ver> CLI 所在目录(通常 /usr/bin),便于测试注入。
func detectDebianInstalls(root, binDir string) []debianInstall {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []debianInstall
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ver := e.Name()
		if !ValidVersion(ver) {
			continue
		}
		fpmDir := filepath.Join(root, ver, "fpm")
		hasFpm := false
		if fi, err := os.Stat(fpmDir); err == nil && fi.IsDir() {
			hasFpm = true
		}
		out = append(out, debianInstall{
			Version:  ver,
			PhpBin:   filepath.Join(binDir, "php"+ver),
			IniPath:  filepath.Join(fpmDir, "php.ini"),
			PoolConf: filepath.Join(fpmDir, "pool.d", "www.conf"),
			FpmUnit:  "php" + ver + "-fpm",
			HasFpm:   hasFpm,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

// probeFpmActiveProc 在无 systemd 时退化探测:扫 procRoot(通常 /proc)下各进程的
// comm,命中 "php-fpm<ver>"(Debian fpm 主进程名)即认为该单元在运行。
// 探测不到 / procRoot 不可读 → false,绝不报错。unit 形如 "php8.3-fpm"。
func probeFpmActiveProc(unit, procRoot string) bool {
	ver := debianUnitVersion(unit)
	if ver == "" {
		return false
	}
	want := "php-fpm" + ver
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// 仅看数字 PID 目录。
		if !isAllDigits(e.Name()) {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == want {
			return true
		}
	}
	return false
}

// debianUnitVersion 从 "php8.3-fpm" 抽出 "8.3";不匹配该形态返回 ""。
func debianUnitVersion(unit string) string {
	if !strings.HasPrefix(unit, "php") || !strings.HasSuffix(unit, "-fpm") {
		return ""
	}
	ver := strings.TrimSuffix(strings.TrimPrefix(unit, "php"), "-fpm")
	if !ValidVersion(ver) {
		return ""
	}
	return ver
}

// isAllDigits 报告 s 非空且仅含十进制数字。
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
