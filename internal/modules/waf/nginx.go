package waf

import (
	"fmt"
	"os/exec"
	"strings"
)

// Nginx 抽象对 nginx 二进制的命令调用,便于 mock 测试。
// 实现必须用参数数组执行(绝不拼 shell),所有入参由调用方保证已校验。
type Nginx interface {
	// Available 报告 nginx 是否可用(供 HealthCheck)。
	Available() error
	// Test 校验给定配置文件路径的语法(nginx -t -c path),返回合并输出。
	Test(confPath string) (string, error)
	// Reload 重载 nginx 配置(nginx -s reload),返回合并输出。
	Reload() (string, error)
}

// execNginx 是 Nginx 的真实实现:调用系统 nginx 二进制。
type execNginx struct{}

// NewNginx 返回基于系统 nginx 二进制的 Nginx 实现。
func NewNginx() Nginx { return execNginx{} }

func (execNginx) Available() error {
	if _, err := exec.LookPath("nginx"); err != nil {
		return fmt.Errorf("waf: nginx binary not found in PATH")
	}
	return nil
}

// Test 用 nginx -t 校验整体配置(确保新 include 不破坏主配置)。
// confPath 指向主配置时校验全局;调用方负责传入受控路径。
func (execNginx) Test(confPath string) (string, error) {
	args := []string{"-t"}
	if confPath != "" {
		args = append(args, "-c", confPath)
	}
	return runNginx(args)
}

func (execNginx) Reload() (string, error) {
	return runNginx([]string{"-s", "reload"})
}

// runNginx 用参数数组执行 nginx,返回 TrimSpace 后的合并输出。
func runNginx(args []string) (string, error) {
	out, err := exec.Command("nginx", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("nginx %s: %w", strings.Join(args, " "), err)
	}
	return text, nil
}
