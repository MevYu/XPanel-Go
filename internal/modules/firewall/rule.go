package firewall

import (
	"fmt"
	"strconv"
	"strings"
)

// PortRule 一条端口规则:支持单端口或端口段、协议、来源限制与备注。
// Port 形如 "80" 或 "8000-9000"。Source 空表示任意来源。
type PortRule struct {
	Action  string `json:"action"`  // allow | deny
	Port    string `json:"port"`    // "80" 或 "8000-9000"
	Proto   string `json:"proto"`   // tcp | udp
	Source  string `json:"source"`  // IP/CIDR,空=任意
	Comment string `json:"comment"` // 可选备注
}

// Validate 严格校验,任一不合法即拒,绝不进命令行。
func (r PortRule) Validate() error {
	if !validAction(r.Action) {
		return fmt.Errorf("firewall: action %q not allowed (allow|deny)", r.Action)
	}
	if _, _, _, err := parsePortSpec(r.Port); err != nil {
		return err
	}
	if !validProto(r.Proto) {
		return fmt.Errorf("firewall: proto %q not allowed (tcp|udp)", r.Proto)
	}
	if !validSource(r.Source) {
		return fmt.Errorf("firewall: source %q is not a valid IP/CIDR", r.Source)
	}
	if !validComment(r.Comment) {
		return fmt.Errorf("firewall: comment is too long or contains control characters")
	}
	return nil
}

// portToken 返回端口标记,区间用指定分隔符 sep。ufw 用 ":",firewalld rich rule 用 "-"。
func (r PortRule) portToken(sep string) string {
	from, to, isRange, _ := parsePortSpec(r.Port)
	if isRange {
		return strconv.Itoa(from) + sep + strconv.Itoa(to)
	}
	return strconv.Itoa(from)
}

// IPAction 黑白名单动作。
type IPAction string

const (
	IPBlock IPAction = "block" // 封禁:拒绝该 IP 的所有流量
	IPTrust IPAction = "trust" // 信任:放行该 IP 的所有流量
)

// IPRule 黑/白名单条目:对某 IP/CIDR 整体封禁或信任。
type IPRule struct {
	Action IPAction `json:"action"` // block | trust
	IP     string   `json:"ip"`     // IP 或 CIDR,必填
}

// Validate 校验 IP 规则。
func (r IPRule) Validate() error {
	if r.Action != IPBlock && r.Action != IPTrust {
		return fmt.Errorf("firewall: ip action %q not allowed (block|trust)", r.Action)
	}
	if !validIP(r.IP) {
		return fmt.Errorf("firewall: ip %q is not a valid IP/CIDR", r.IP)
	}
	return nil
}

// Status 防火墙状态总览。
type Status struct {
	Backend   string `json:"backend"`   // ufw | firewalld | ""(none)
	Running   bool   `json:"running"`   // 防火墙是否启用/运行
	RuleCount int    `json:"ruleCount"` // 解析出的规则条数
	SSHPort   int    `json:"sshPort"`   // 从 sshd_config 读出的 SSH 端口(0=未知/默认22)
}

// ipFamily 依 IP/CIDR 文本判定 family,供 firewalld rich rule 使用。
func ipFamily(s string) string {
	if strings.Contains(s, ":") {
		return "ipv6"
	}
	return "ipv4"
}
