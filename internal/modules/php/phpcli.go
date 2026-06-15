// Package php 实现 PHP 多版本管理模块:检测已安装版本、查看/编辑 php.ini 常用项、
// 管理扩展(列出/启用/禁用)、重启对应 php-fpm。任何进入 exec 参数或写入 php.ini
// 的输入都先经严格白名单校验(防命令注入 / 配置注入)。
package php

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// 版本号白名单:仅数字与点(如 "8.1"、"7.4.33")。挡掉任何可用于路径逃逸 / 注入的字符。
var versionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// 扩展名白名单:字母数字与下划线(如 "redis"、"opcache"、"pdo_mysql")。
var extNameRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// ValidVersion 报告 v 是合法 PHP 版本号(仅数字与点)。
func ValidVersion(v string) bool { return v != "" && versionRe.MatchString(v) }

// ValidExtName 报告 name 是合法扩展名(字母数字下划线)。
func ValidExtName(name string) bool { return name != "" && extNameRe.MatchString(name) }

// PHPRunner 抽象对 php / php-fpm 服务的命令调用,便于 mock 测试。
// 实现必须用参数数组执行(绝不拼 shell),所有入参由调用方保证已白名单校验。
type PHPRunner interface {
	// Available 报告 PHP 工具链是否可用(供 HealthCheck)。
	Available() error
	// Version 执行 <bin> -v,返回合并输出。bin 为某版本的 php 可执行路径。
	Version(bin string) (string, error)
	// Modules 执行 <bin> -m 列出已加载扩展,返回合并输出(每行一个扩展名)。
	Modules(bin string) (string, error)
	// FpmAction 对 php-fpm 服务单元执行 systemctl <verb> <unit>,返回合并输出。
	FpmAction(verb, unit string) (string, error)
}

// execRunner 是 PHPRunner 的真实实现:调用系统 php / systemctl 二进制。
type execRunner struct{}

// NewRunner 返回基于系统二进制的 PHPRunner 实现。
func NewRunner() PHPRunner { return execRunner{} }

func (execRunner) Available() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("php: systemctl not found in PATH")
	}
	return nil
}

func (execRunner) Version(bin string) (string, error) {
	out, err := exec.Command(bin, "-v").CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("php -v: %w", err)
	}
	return text, nil
}

func (execRunner) Modules(bin string) (string, error) {
	out, err := exec.Command(bin, "-m").CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("php -m: %w", err)
	}
	return text, nil
}

// fpmVerbs 允许的 systemctl 动词。start/stop/restart 为状态变更,status 只读。
var fpmVerbs = map[string]bool{"start": true, "stop": true, "restart": true, "status": true}

func (execRunner) FpmAction(verb, unit string) (string, error) {
	if !fpmVerbs[verb] {
		return "", fmt.Errorf("php: fpm verb %q not allowed", verb)
	}
	out, err := exec.Command("systemctl", "--no-pager", verb, unit).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil && verb != "status" {
		return text, fmt.Errorf("systemctl %s %s: %w", verb, unit, err)
	}
	return text, nil
}
