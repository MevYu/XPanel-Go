package files

import (
	"errors"
	"os/exec"
	"os/user"
	"syscall"
)

// isCrossDevice 报告 err 是否为跨设备 rename 错误(EXDEV),需 copy+remove 兜底。
func isCrossDevice(err error) bool {
	return errors.Is(err, syscall.EXDEV)
}

// runChown 执行系统 chown,args 为参数数组(绝不拼 shell)。
func runChown(args []string) error {
	return exec.Command("chown", args...).Run()
}

// lookupSystemUser 校验用户存在,返回规范用户名。
func lookupSystemUser(name string) (string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// lookupSystemGroup 校验组存在,返回组名。
func lookupSystemGroup(name string) (string, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return "", err
	}
	return g.Name, nil
}
