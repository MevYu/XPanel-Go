package system

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// 单元名白名单:字母数字 . _ - @,长度受限。拒绝任何可用于注入的字符。
var unitNameRe = regexp.MustCompile(`^[a-zA-Z0-9._@-]{1,128}$`)

func ValidUnitName(name string) bool {
	return unitNameRe.MatchString(name)
}

// 允许的 systemctl 动词。status 只读;其余为状态变更(调用方需做 RBAC)。
var allowedVerbs = map[string]bool{
	"status": true, "start": true, "stop": true, "restart": true,
}

// ServiceAction 用参数数组执行 systemctl <verb> <unit>,绝不拼接 shell。
// 返回命令合并输出。校验 verb 与 unit 名,挡注入。
func ServiceAction(verb, unit string) (string, error) {
	if !allowedVerbs[verb] {
		return "", fmt.Errorf("systemctl: verb %q not allowed", verb)
	}
	if !ValidUnitName(unit) {
		return "", fmt.Errorf("systemctl: invalid unit name %q", unit)
	}
	// systemctl status 退出码非 0 属正常(服务停止),不当错误抛。
	out, err := exec.Command("systemctl", "--no-pager", verb, unit).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil && verb != "status" {
		return text, fmt.Errorf("systemctl %s %s: %w", verb, unit, err)
	}
	return text, nil
}

// SystemctlAvailable 供模块 HealthCheck 用:systemctl 是否在 PATH。
func SystemctlAvailable() error {
	_, err := exec.LookPath("systemctl")
	return err
}
