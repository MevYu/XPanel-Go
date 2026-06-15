package system

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// Backend 标识检测到的防火墙后端。
type Backend string

const (
	BackendNone      Backend = ""
	BackendUFW       Backend = "ufw"
	BackendFirewalld Backend = "firewalld"
)

// DetectBackend 探测可用后端,优先 ufw,其次 firewalld;都不在返回 BackendNone。
// 仅看二进制是否在 PATH,不执行状态查询(HealthCheck 要快、无副作用)。
func DetectBackend() Backend {
	if _, err := exec.LookPath("ufw"); err == nil {
		return BackendUFW
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		return BackendFirewalld
	}
	return BackendNone
}

// FirewallAvailable 供模块 HealthCheck:无任何后端则不允许启用。
func FirewallAvailable() error {
	if DetectBackend() == BackendNone {
		return fmt.Errorf("firewall: no supported backend (ufw/firewalld) found")
	}
	return nil
}

// ValidPort 端口须在 1..65535。
func ValidPort(p int) bool { return p >= 1 && p <= 65535 }

var allowedProtos = map[string]bool{"tcp": true, "udp": true}

// ValidProto 协议白名单:仅 tcp/udp(小写)。
func ValidProto(p string) bool { return allowedProtos[p] }

// ValidSource 校验来源:空串表示任意来源(合法);否则须为合法 IP 或 CIDR。
func ValidSource(s string) bool {
	if s == "" {
		return true
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// FirewallRule 描述一条端口规则。Source 为空表示任意来源。
type FirewallRule struct {
	Action string `json:"action"` // allow | deny
	Port   int    `json:"port"`
	Proto  string `json:"proto"` // tcp | udp
	Source string `json:"source"`
}

var allowedActions = map[string]bool{"allow": true, "deny": true}

// Validate 严格校验,任一不合法即拒,绝不进命令行。
func (r FirewallRule) Validate() error {
	if !allowedActions[r.Action] {
		return fmt.Errorf("firewall: action %q not allowed (allow|deny)", r.Action)
	}
	if !ValidPort(r.Port) {
		return fmt.Errorf("firewall: port %d out of range (1-65535)", r.Port)
	}
	if !ValidProto(r.Proto) {
		return fmt.Errorf("firewall: proto %q not allowed (tcp|udp)", r.Proto)
	}
	if !ValidSource(r.Source) {
		return fmt.Errorf("firewall: source %q is not a valid IP/CIDR", r.Source)
	}
	return nil
}

// ufwArgs 构造 ufw 命令参数数组(不含 "ufw" 本身)。add=false 时为删除。
// 形如:ufw allow proto tcp from 10.0.0.0/8 to any port 80
func (r FirewallRule) ufwArgs(add bool) []string {
	args := make([]string, 0, 10)
	if !add {
		args = append(args, "delete")
	}
	args = append(args, r.Action, "proto", r.Proto)
	if r.Source != "" {
		args = append(args, "from", r.Source)
	} else {
		args = append(args, "from", "any")
	}
	args = append(args, "to", "any", "port", strconv.Itoa(r.Port))
	return args
}

// firewalldArgs 构造 firewall-cmd 永久 rich rule 参数数组。
// 形如:firewall-cmd --permanent --add-rich-rule=rule family=... port port=80 protocol=tcp accept
func (r FirewallRule) firewalldArgs(add bool) []string {
	op := "--add-rich-rule"
	if !add {
		op = "--remove-rich-rule"
	}
	var b strings.Builder
	b.WriteString("rule ")
	switch {
	case r.Source == "":
		// 无 source 限制,family 由 port 隐含;省略 family 让 firewalld 自适应。
	case strings.Contains(r.Source, ":"):
		b.WriteString("family=ipv6 source address=" + r.Source + " ")
	default:
		b.WriteString("family=ipv4 source address=" + r.Source + " ")
	}
	b.WriteString("port port=" + strconv.Itoa(r.Port) + " protocol=" + r.Proto + " ")
	if r.Action == "allow" {
		b.WriteString("accept")
	} else {
		b.WriteString("reject")
	}
	return []string{"--permanent", op + "=" + b.String()}
}

// ApplyRule 应用一条规则(校验后用参数数组执行,绝不拼 shell)。返回命令合并输出。
func ApplyRule(r FirewallRule, add bool) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	switch DetectBackend() {
	case BackendUFW:
		return run("ufw", append([]string{"--force"}, r.ufwArgs(add)...))
	case BackendFirewalld:
		out, err := run("firewall-cmd", r.firewalldArgs(add))
		if err != nil {
			return out, err
		}
		// 永久规则需 reload 生效。
		reloadOut, reloadErr := run("firewall-cmd", []string{"--reload"})
		return out + "\n" + reloadOut, reloadErr
	default:
		return "", fmt.Errorf("firewall: no supported backend")
	}
}

// ListRules 列出当前规则(只读)。ufw 用 status numbered,firewalld 用 --list-all。
func ListRules() (string, error) {
	switch DetectBackend() {
	case BackendUFW:
		return run("ufw", []string{"status", "numbered"})
	case BackendFirewalld:
		return run("firewall-cmd", []string{"--list-all"})
	default:
		return "", fmt.Errorf("firewall: no supported backend")
	}
}

// SetEnabled 启用/禁用防火墙(危险:禁用会清空保护)。
func SetEnabled(enable bool) (string, error) {
	switch DetectBackend() {
	case BackendUFW:
		verb := "enable"
		if !enable {
			verb = "disable"
		}
		return run("ufw", []string{"--force", verb})
	case BackendFirewalld:
		// firewalld 通过 systemctl 控制服务运行态。
		verb := "start"
		if !enable {
			verb = "stop"
		}
		return run("systemctl", []string{verb, "firewalld"})
	default:
		return "", fmt.Errorf("firewall: no supported backend")
	}
}

// run 执行命令并返回 TrimSpace 后的合并输出。
func run(name string, args []string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return text, nil
}
