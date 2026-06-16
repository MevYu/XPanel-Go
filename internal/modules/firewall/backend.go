package firewall

import (
	"os/exec"
	"strings"
)

// Backend 抽象具体防火墙后端(ufw/firewalld),便于 mock 测试。
// 所有写操作均经参数数组执行,绝不拼 shell。
type Backend interface {
	Name() string // "ufw" | "firewalld"

	Status() (Status, error) // 状态总览(后端类型/运行态/规则数)
	ListPortRules() ([]PortRule, error)
	ApplyPortRule(r PortRule, add bool) (string, error)

	ApplyIPRule(r IPRule, add bool) (string, error) // 黑白名单
	SetPing(allow bool) (string, error)             // ICMP echo 开关

	SetEnabled(enable bool) (string, error) // 启停防火墙
}

// runner 是 exec 间接层,测试用 mock 替换;生产用 execRunner 真正执行。
type runner interface {
	run(name string, args []string) (string, error)
}

type execRunner struct{}

// run 执行命令并返回 TrimSpace 后的合并输出。绝不拼 shell。
func (execRunner) run(name string, args []string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, &cmdError{name: name, args: args, err: err, output: text}
	}
	return text, nil
}

type cmdError struct {
	name   string
	args   []string
	err    error
	output string
}

func (e *cmdError) Error() string {
	return e.name + " " + strings.Join(e.args, " ") + ": " + e.err.Error()
}

func (e *cmdError) Unwrap() error { return e.err }

// detectBackend 探测可用后端:优先 ufw,其次 firewalld;都不在返回 nil。
// 仅看二进制是否在 PATH,不执行状态查询(要快、无副作用)。
func detectBackend(run runner) Backend {
	if _, err := exec.LookPath("ufw"); err == nil {
		return &ufwBackend{run: run}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		return &firewalldBackend{run: run}
	}
	return nil
}
