package dns

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// 严格白名单校验:域名、记录名、记录类型、记录值。
// 目的是挡注入(进 zone 文件 / provider API / exec)与畸形数据。绝不放行可疑字符。

var (
	errBadDomain = errors.New("invalid domain name")
	errBadType   = errors.New("invalid record type")
	errBadName   = errors.New("invalid record name")
	errBadValue  = errors.New("invalid record value")
	errBadTTL    = errors.New("ttl out of range (60..604800)")
	errBadPrio   = errors.New("priority out of range (0..65535)")
)

// supportedTypes 是允许管理的记录类型白名单。
var supportedTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true,
	"TXT": true, "NS": true, "SRV": true, "CAA": true,
}

// validType 报告记录类型是否在白名单内(大写)。
func validType(t string) bool { return supportedTypes[t] }

// needsPriority 报告该类型是否带优先级(MX/SRV)。
func needsPriority(t string) bool { return t == "MX" || t == "SRV" }

// validDomain 校验一个 zone 域名:点分 label,每个 label 1..63 字符,
// 仅 [a-z0-9-],不以连字符开头/结尾,总长 ≤253。大小写不敏感,统一存小写。
func validDomain(d string) bool {
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 { // zone 至少要有一个点(如 example.com)
		return false
	}
	for _, l := range labels {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

// validRecordName 校验记录名(相对 zone 的子名)。允许:
// "@"(zone apex)、"*"(通配,仅作为最左 label)、点分子域(如 "www" / "a.b")。
func validRecordName(name string) bool {
	if name == "" {
		return false
	}
	if name == "@" {
		return true // zone apex
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) > 127 {
		return false
	}
	for i, l := range labels {
		if l == "*" {
			if i != 0 {
				return false // 通配只能在最左
			}
			continue
		}
		if !validLabel(l) {
			return false
		}
	}
	return true
}

// validLabel 校验单个 DNS label:1..63 字符,[a-z0-9-],不以 '-' 起止,下划线允许(用于 _dmarc 等)。
func validLabel(l string) bool {
	if len(l) == 0 || len(l) > 63 {
		return false
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// validValue 按类型校验记录值,挡注入字符(换行/分号/引号等会破坏 zone 文件)。
func validValue(t, v string) bool {
	if v == "" || len(v) > 512 {
		return false
	}
	// 任何类型都禁止控制字符与 zone 文件元字符(换行/回车),否则可越行注入。
	if strings.ContainsAny(v, "\n\r\x00") {
		return false
	}
	switch t {
	case "A":
		ip := net.ParseIP(v)
		return ip != nil && ip.To4() != nil
	case "AAAA":
		ip := net.ParseIP(v)
		return ip != nil && ip.To4() == nil
	case "CNAME", "NS":
		return validHostTarget(v)
	case "MX":
		return validHostTarget(v)
	case "TXT":
		// TXT 允许较宽字符集,但禁止裸双引号/分号/反斜杠以免破坏 zone 引用。
		return !strings.ContainsAny(v, "\";\\")
	case "SRV":
		return validSRVTarget(v)
	case "CAA":
		return validCAA(v)
	}
	return false
}

// validHostTarget 校验主机名目标(CNAME/NS/MX 的目标):FQDN label 串,允许末尾点。
func validHostTarget(v string) bool {
	v = strings.TrimSuffix(v, ".")
	if v == "" || len(v) > 253 {
		return false
	}
	for _, l := range strings.Split(v, ".") {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

// validSRVTarget 校验 SRV 记录值格式 "weight port target"。priority 单列字段,不在此。
func validSRVTarget(v string) bool {
	parts := strings.Fields(v)
	if len(parts) != 3 {
		return false
	}
	for _, n := range parts[:2] {
		x, err := strconv.Atoi(n)
		if err != nil || x < 0 || x > 65535 {
			return false
		}
	}
	if parts[2] == "." {
		return true // "." 表无目标
	}
	return validHostTarget(parts[2])
}

// validCAA 校验 CAA 记录值 "flags tag value",tag ∈ {issue,issuewild,iodef}。
func validCAA(v string) bool {
	parts := strings.SplitN(v, " ", 3)
	if len(parts) != 3 {
		return false
	}
	flags, err := strconv.Atoi(parts[0])
	if err != nil || flags < 0 || flags > 255 {
		return false
	}
	switch parts[1] {
	case "issue", "issuewild", "iodef":
	default:
		return false
	}
	// value 必须双引号包裹且内部无引号(zone 语法)。
	val := parts[2]
	if len(val) < 2 || val[0] != '"' || val[len(val)-1] != '"' {
		return false
	}
	return !strings.ContainsAny(val[1:len(val)-1], "\";\\")
}

const (
	minTTL = 60
	maxTTL = 604800
)

// validTTL 报告 ttl 是否在合理范围。
func validTTL(ttl int) bool { return ttl >= minTTL && ttl <= maxTTL }

// validPriority 报告优先级是否在 0..65535。
func validPriority(p int) bool { return p >= 0 && p <= 65535 }
