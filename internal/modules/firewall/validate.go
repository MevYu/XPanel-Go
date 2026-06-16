package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// 端口/端口段/协议/来源/备注的严格校验。任一不合法即拒,绝不进命令行。

const maxComment = 128

var (
	allowedActions = map[string]bool{"allow": true, "deny": true}
	allowedProtos  = map[string]bool{"tcp": true, "udp": true}
)

// validPort 端口须在 1..65535。
func validPort(p int) bool { return p >= 1 && p <= 65535 }

// validProto 协议白名单:tcp/udp(小写)。
func validProto(p string) bool { return allowedProtos[p] }

// validAction 动作白名单:allow/deny。
func validAction(a string) bool { return allowedActions[a] }

// validSource 来源校验:空串表示任意(合法);否则须为合法 IP 或 CIDR。
func validSource(s string) bool {
	if s == "" {
		return true
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// validIP 单 IP/CIDR(非空):黑白名单条目须明确指定一个地址或网段。
func validIP(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// validComment 备注:可空;非空时禁止控制字符,限长。
// 备注以参数数组传给 ufw 的 comment,不经 shell;仍拒绝换行/控制字符,
// 避免污染规则列表与日志。
func validComment(c string) bool {
	if c == "" {
		return true
	}
	if len(c) > maxComment {
		return false
	}
	for _, r := range c {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// parsePortSpec 解析端口规格:单端口 "80" 或闭区间端口段 "8000-9000"。
// 返回归一化 from/to(单端口时 from==to)与是否为区间;区间要求 from<=to 且均合法。
func parsePortSpec(spec string) (from, to int, isRange bool, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, false, fmt.Errorf("firewall: empty port spec")
	}
	if !strings.Contains(spec, "-") {
		p, perr := strconv.Atoi(spec)
		if perr != nil || !validPort(p) {
			return 0, 0, false, fmt.Errorf("firewall: port %q out of range (1-65535)", spec)
		}
		return p, p, false, nil
	}
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return 0, 0, false, fmt.Errorf("firewall: malformed port range %q", spec)
	}
	lo, loErr := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, hiErr := strconv.Atoi(strings.TrimSpace(parts[1]))
	if loErr != nil || hiErr != nil || !validPort(lo) || !validPort(hi) {
		return 0, 0, false, fmt.Errorf("firewall: port range %q out of range (1-65535)", spec)
	}
	if lo > hi {
		return 0, 0, false, fmt.Errorf("firewall: port range %q has from>to", spec)
	}
	if lo == hi {
		return lo, hi, false, nil
	}
	return lo, hi, true, nil
}
