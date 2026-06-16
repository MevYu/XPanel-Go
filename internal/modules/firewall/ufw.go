package firewall

import (
	"strings"
)

// ufwBackend 用 ufw 命令实现 Backend。
type ufwBackend struct{ run runner }

func (*ufwBackend) Name() string { return "ufw" }

// portArgs 构造端口规则参数(不含 "ufw"/"--force")。add=false 时前置 "delete"。
// 形如:allow proto tcp from 10.0.0.0/8 to any port 8000:9000 comment "x"
func (*ufwBackend) portArgs(r PortRule, add bool) []string {
	args := make([]string, 0, 12)
	if !add {
		args = append(args, "delete")
	}
	args = append(args, r.Action, "proto", r.Proto)
	if r.Source != "" {
		args = append(args, "from", r.Source)
	} else {
		args = append(args, "from", "any")
	}
	args = append(args, "to", "any", "port", r.portToken(":"))
	if r.Comment != "" {
		args = append(args, "comment", r.Comment)
	}
	return args
}

// ipArgs 构造黑白名单参数。block=deny from <ip>;trust=allow from <ip>。
func (*ufwBackend) ipArgs(r IPRule, add bool) []string {
	verb := "deny"
	if r.Action == IPTrust {
		verb = "allow"
	}
	args := make([]string, 0, 4)
	if !add {
		args = append(args, "delete")
	}
	args = append(args, verb, "from", r.IP)
	return args
}

func (b *ufwBackend) ApplyPortRule(r PortRule, add bool) (string, error) {
	return b.run.run("ufw", append([]string{"--force"}, b.portArgs(r, add)...))
}

func (b *ufwBackend) ApplyIPRule(r IPRule, add bool) (string, error) {
	return b.run.run("ufw", append([]string{"--force"}, b.ipArgs(r, add)...))
}

// SetPing 切换 ICMP echo。ufw 通过 /etc/ufw/before.rules 控制 ICMP,
// 命令行无直接开关;此处用 default 路由级 deny/allow 不可行,故改写不在范围内。
// 为避免误导,ufw 后端以 routing 不支持返回明确错误,由 handler 转 501。
func (b *ufwBackend) SetPing(allow bool) (string, error) {
	return "", errPingUnsupported
}

func (b *ufwBackend) SetEnabled(enable bool) (string, error) {
	verb := "enable"
	if !enable {
		verb = "disable"
	}
	return b.run.run("ufw", []string{"--force", verb})
}

func (b *ufwBackend) Status() (Status, error) {
	out, err := b.run.run("ufw", []string{"status", "numbered"})
	if err != nil {
		return Status{Backend: "ufw"}, err
	}
	st := Status{Backend: "ufw"}
	st.Running = strings.Contains(out, "Status: active")
	rules, _ := parseUFWRules(out)
	st.RuleCount = len(rules)
	return st, nil
}

func (b *ufwBackend) ListPortRules() ([]PortRule, error) {
	out, err := b.run.run("ufw", []string{"status", "numbered"})
	if err != nil {
		return nil, err
	}
	return parseUFWRules(out)
}

// parseUFWRules 解析 `ufw status numbered` 输出为结构化端口规则。
// 仅提取能可靠解析的端口/协议/动作/来源行;无法解析的行跳过(尽力而为)。
// 典型行:
// [ 1] 8000:9000/tcp             ALLOW IN    10.0.0.0/8                 # web
// [ 2] 22/tcp                    ALLOW IN    Anywhere
func parseUFWRules(out string) ([]PortRule, error) {
	var rules []PortRule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		// 去掉前缀 [ n]
		close := strings.Index(line, "]")
		if close < 0 {
			continue
		}
		body := strings.TrimSpace(line[close+1:])
		// 拆备注
		comment := ""
		if i := strings.Index(body, "#"); i >= 0 {
			comment = strings.TrimSpace(body[i+1:])
			body = strings.TrimSpace(body[:i])
		}
		fields := strings.Fields(body)
		if len(fields) < 2 {
			continue
		}
		target := fields[0] // 形如 8000:9000/tcp 或 22/tcp 或 22
		slash := strings.Index(target, "/")
		if slash < 0 {
			continue // 无协议的(如 v6 重复行/应用名),跳过
		}
		portPart := target[:slash]
		proto := target[slash+1:]
		if !validProto(proto) {
			continue
		}
		// 端口段 8000:9000 -> 8000-9000
		port := strings.ReplaceAll(portPart, ":", "-")
		if _, _, _, err := parsePortSpec(port); err != nil {
			continue
		}
		// 动作:ALLOW/DENY (IN/OUT)
		action := ""
		switch {
		case strings.Contains(body, "ALLOW"):
			action = "allow"
		case strings.Contains(body, "DENY"), strings.Contains(body, "REJECT"):
			action = "deny"
		default:
			continue
		}
		// 来源:最后一列若为具体 IP/CIDR 则记录,Anywhere 视为任意。
		source := ""
		if last := fields[len(fields)-1]; validIP(last) {
			source = last
		}
		rules = append(rules, PortRule{
			Action:  action,
			Port:    port,
			Proto:   proto,
			Source:  source,
			Comment: comment,
		})
	}
	return rules, nil
}
