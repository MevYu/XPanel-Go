package firewall

import (
	"errors"
	"strings"
)

var errPingUnsupported = errors.New("firewall: ping toggle not supported by this backend")

// firewalldBackend 用 firewall-cmd 实现 Backend(永久 rich rule + reload)。
type firewalldBackend struct{ run runner }

func (*firewalldBackend) Name() string { return "firewalld" }

// portRichRule 构造端口 rich rule 文本(不含 op 前缀)。
// 形如:rule family=ipv4 source address=10.0.0.0/8 port port=8000-9000 protocol=tcp accept
func (*firewalldBackend) portRichRule(r PortRule) string {
	var b strings.Builder
	b.WriteString("rule ")
	if r.Source != "" {
		b.WriteString("family=" + ipFamily(r.Source) + " source address=" + r.Source + " ")
	}
	b.WriteString("port port=" + r.portToken("-") + " protocol=" + r.Proto + " ")
	if r.Action == "allow" {
		b.WriteString("accept")
	} else {
		b.WriteString("reject")
	}
	return b.String()
}

// ipRichRule 构造黑白名单 rich rule 文本:对整 IP/CIDR accept/drop。
func (*firewalldBackend) ipRichRule(r IPRule) string {
	verb := "drop"
	if r.Action == IPTrust {
		verb = "accept"
	}
	return "rule family=" + ipFamily(r.IP) + " source address=" + r.IP + " " + verb
}

func (b *firewalldBackend) portArgs(r PortRule, add bool) []string {
	op := "--add-rich-rule"
	if !add {
		op = "--remove-rich-rule"
	}
	return []string{"--permanent", op + "=" + b.portRichRule(r)}
}

func (b *firewalldBackend) ipArgs(r IPRule, add bool) []string {
	op := "--add-rich-rule"
	if !add {
		op = "--remove-rich-rule"
	}
	return []string{"--permanent", op + "=" + b.ipRichRule(r)}
}

// applyAndReload 执行永久变更后 reload 生效。
func (b *firewalldBackend) applyAndReload(args []string) (string, error) {
	out, err := b.run.run("firewall-cmd", args)
	if err != nil {
		return out, err
	}
	reloadOut, reloadErr := b.run.run("firewall-cmd", []string{"--reload"})
	return out + "\n" + reloadOut, reloadErr
}

func (b *firewalldBackend) ApplyPortRule(r PortRule, add bool) (string, error) {
	return b.applyAndReload(b.portArgs(r, add))
}

func (b *firewalldBackend) ApplyIPRule(r IPRule, add bool) (string, error) {
	return b.applyAndReload(b.ipArgs(r, add))
}

// SetPing 切换 ICMP echo:block=拒绝 echo-request,allow=移除该 block。
func (b *firewalldBackend) SetPing(allow bool) (string, error) {
	op := "--add-icmp-block=echo-request"
	if allow {
		op = "--remove-icmp-block=echo-request"
	}
	return b.applyAndReload([]string{"--permanent", op})
}

func (b *firewalldBackend) SetEnabled(enable bool) (string, error) {
	// firewalld 经 systemctl 控制服务运行态。
	verb := "start"
	if !enable {
		verb = "stop"
	}
	return b.run.run("systemctl", []string{verb, "firewalld"})
}

func (b *firewalldBackend) Status() (Status, error) {
	st := Status{Backend: "firewalld"}
	state, _ := b.run.run("firewall-cmd", []string{"--state"})
	st.Running = strings.Contains(state, "running")
	rules, err := b.ListPortRules()
	if err != nil {
		return st, err
	}
	st.RuleCount = len(rules)
	return st, nil
}

func (b *firewalldBackend) ListPortRules() ([]PortRule, error) {
	out, err := b.run.run("firewall-cmd", []string{"--list-all"})
	if err != nil {
		return nil, err
	}
	return parseFirewalldRules(out), nil
}

// parseFirewalldRules 从 `firewall-cmd --list-all` 输出提取规则。
// 解析两类:
//  1. ports: 8000-9000/tcp 22/tcp  (无来源限制)
//  2. rich rules: rule family="ipv4" source address="10.0.0.0/8" port port="80" protocol="tcp" accept
func parseFirewalldRules(out string) []PortRule {
	var rules []PortRule
	lines := strings.Split(out, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "ports:"):
			rules = append(rules, parseFirewalldPortsLine(strings.TrimPrefix(line, "ports:"))...)
		case strings.HasPrefix(line, "rule "):
			if r, ok := parseFirewalldRichRule(line); ok {
				rules = append(rules, r)
			}
		}
	}
	return rules
}

// parseFirewalldPortsLine 解析形如 " 22/tcp 8000-9000/udp" 的 ports 行。
func parseFirewalldPortsLine(s string) []PortRule {
	var rules []PortRule
	for _, tok := range strings.Fields(s) {
		slash := strings.Index(tok, "/")
		if slash < 0 {
			continue
		}
		port := tok[:slash]
		proto := tok[slash+1:]
		if !validProto(proto) {
			continue
		}
		if _, _, _, err := parsePortSpec(port); err != nil {
			continue
		}
		rules = append(rules, PortRule{Action: "allow", Port: port, Proto: proto})
	}
	return rules
}

// parseFirewalldRichRule 解析端口型 rich rule(含 port=... protocol=...)。
// 非端口型(纯 source accept/drop 黑白名单)返回 ok=false,不计入端口规则。
func parseFirewalldRichRule(line string) (PortRule, bool) {
	port := richAttr(line, "port port=")
	proto := richAttr(line, "protocol=")
	if port == "" || proto == "" {
		return PortRule{}, false
	}
	if !validProto(proto) {
		return PortRule{}, false
	}
	if _, _, _, err := parsePortSpec(port); err != nil {
		return PortRule{}, false
	}
	action := "allow"
	if strings.Contains(line, " reject") || strings.Contains(line, " drop") {
		action = "deny"
	}
	source := richAttr(line, "source address=")
	if source != "" && !validIP(source) {
		source = ""
	}
	return PortRule{Action: action, Port: port, Proto: proto, Source: source}, true
}

// richAttr 取 rich rule 中 key 后的值,去除可选引号,到下一个空白为止。
func richAttr(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key):]
	if strings.HasPrefix(rest, "\"") {
		rest = rest[1:]
		if j := strings.Index(rest, "\""); j >= 0 {
			return rest[:j]
		}
		return ""
	}
	return strings.Fields(rest)[0]
}
