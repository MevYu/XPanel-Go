package waf

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// 严格校验是本模块的安全核心:任何写进 nginx 配置的值都必须先过 Validate,
// 绝不把未校验输入拼进配置模板(防配置注入 / 指令逃逸)。

// nginx 配置里有特殊语义的字符:用于拒绝可能逃出字符串字面量 / 注入新指令的输入。
const nginxMetaChars = "\n\r;{}\"'\\$#"

// hasNginxMeta 报告 s 是否含会破坏 nginx 配置语法的元字符。
func hasNginxMeta(s string) bool { return strings.ContainsAny(s, nginxMetaChars) }

// validCIDROrIP 报告 s 是合法单 IP 或 CIDR(两者都是 nginx allow/deny 的合法参数)。
func validCIDROrIP(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// patternForbidden 是正则模式里绝对禁止的字符:它们能逃出 nginx 双引号串或注入变量。
//   - " 关闭字符串字面量
//   - $ 在 nginx 串内触发变量插值
//   - 换行/回车/NUL 截断配置行
const patternForbidden = "\"$\n\r\x00"

// validPattern 校验正则模式可安全嵌入 nginx 的 "~*...";。
func validPattern(p string) error {
	if strings.ContainsAny(p, patternForbidden) {
		return fmt.Errorf("waf: match pattern contains forbidden characters (no \" $ or newlines)")
	}
	// 尾部奇数个反斜杠会转义收尾的 ",把后续配置吞进字符串。一律拒绝。
	n := 0
	for i := len(p) - 1; i >= 0 && p[i] == '\\'; i-- {
		n++
	}
	if n%2 == 1 {
		return fmt.Errorf("waf: match pattern must not end with an unescaped backslash")
	}
	return nil
}

// IPRule 是一条 IP 黑/白名单规则,落到 nginx allow/deny。
type IPRule struct {
	ID      int64  `json:"id"`
	Action  string `json:"action"` // allow | deny
	CIDR    string `json:"cidr"`   // 单 IP 或 CIDR
	Comment string `json:"comment"`
	Enabled bool   `json:"enabled"`
}

var allowedIPActions = map[string]bool{"allow": true, "deny": true}

// Validate 严格校验 IP 规则:非法即拒,绝不进配置模板。
func (r IPRule) Validate() error {
	if !allowedIPActions[r.Action] {
		return fmt.Errorf("waf: ip action %q not allowed (allow|deny)", r.Action)
	}
	if !validCIDROrIP(r.CIDR) {
		return fmt.Errorf("waf: %q is not a valid IP or CIDR", r.CIDR)
	}
	// CIDR 由 net 解析保证无元字符;comment 不进 nginx 配置,但仍挡换行避免日志/审计污染。
	if hasNginxMeta(r.Comment) {
		return fmt.Errorf("waf: comment contains forbidden characters")
	}
	return nil
}

// MatchRule 是一条 URL / User-Agent 匹配规则,落到 nginx map + return 403/444。
type MatchRule struct {
	ID      int64  `json:"id"`
	Target  string `json:"target"`  // uri | ua
	Pattern string `json:"pattern"` // 正则(由 nginx 解释)
	Action  string `json:"action"`  // block | allow
	Comment string `json:"comment"`
	Enabled bool   `json:"enabled"`
}

var allowedMatchTargets = map[string]bool{"uri": true, "ua": true}
var allowedMatchActions = map[string]bool{"block": true, "allow": true}

// maxPatternLen 限制正则长度,挡超长配置行与体量型 ReDoS。
const maxPatternLen = 512

// Validate 严格校验匹配规则:正则必须能被 Go regexp 编译(nginx 用 PCRE,Go 用 RE2,
// 这里要求 RE2 可编译作为保守上界——拒掉绝大多数畸形/恶意模式),且不含 nginx 元字符。
func (r MatchRule) Validate() error {
	if !allowedMatchTargets[r.Target] {
		return fmt.Errorf("waf: match target %q not allowed (uri|ua)", r.Target)
	}
	if !allowedMatchActions[r.Action] {
		return fmt.Errorf("waf: match action %q not allowed (block|allow)", r.Action)
	}
	if r.Pattern == "" {
		return fmt.Errorf("waf: match pattern is empty")
	}
	if len(r.Pattern) > maxPatternLen {
		return fmt.Errorf("waf: match pattern too long (max %d)", maxPatternLen)
	}
	// 模式总是渲染进 nginx 的 "~*...";(双引号串内)。引号内 ; { } # 无特殊语义,
	// 故放行(正则需要 {} 量词、\ 转义)。只挡能逃出引号串/注入变量的字符:
	// " 关闭串、$ 触发变量插值、换行/NUL 截断行。
	if err := validPattern(r.Pattern); err != nil {
		return err
	}
	if _, err := regexp.Compile(r.Pattern); err != nil {
		return fmt.Errorf("waf: match pattern is not a valid regex: %v", err)
	}
	if hasNginxMeta(r.Comment) {
		return fmt.Errorf("waf: comment contains forbidden characters")
	}
	return nil
}

// CCConfig 是 CC(challenge collapsar)防御参数,落到 nginx limit_req / limit_conn。
type CCConfig struct {
	Enabled    bool `json:"enabled"`
	RatePerSec int  `json:"rate_per_sec"` // 每客户端每秒允许请求数(limit_req rate=Nr/s)
	Burst      int  `json:"burst"`        // 突发缓冲(limit_req burst=N)
	ConnPerIP  int  `json:"conn_per_ip"`  // 单 IP 并发连接上限(limit_conn)
	ZoneSizeMB int  `json:"zone_size_mb"` // 共享内存区大小(MB)
}

// CC 阈值的合理边界:挡 0/负数(会生成无效配置)与离谱大值。
const (
	minRate   = 1
	maxRate   = 100000
	maxBurst  = 100000
	maxConn   = 100000
	minZoneMB = 1
	maxZoneMB = 1024
)

// Validate 校验 CC 参数。Enabled=false 时跳过阈值校验(不会生成限速配置)。
func (c CCConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.RatePerSec < minRate || c.RatePerSec > maxRate {
		return fmt.Errorf("waf: cc rate_per_sec %d out of range (%d-%d)", c.RatePerSec, minRate, maxRate)
	}
	if c.Burst < 0 || c.Burst > maxBurst {
		return fmt.Errorf("waf: cc burst %d out of range (0-%d)", c.Burst, maxBurst)
	}
	if c.ConnPerIP < 0 || c.ConnPerIP > maxConn {
		return fmt.Errorf("waf: cc conn_per_ip %d out of range (0-%d)", c.ConnPerIP, maxConn)
	}
	if c.ZoneSizeMB < minZoneMB || c.ZoneSizeMB > maxZoneMB {
		return fmt.Errorf("waf: cc zone_size_mb %d out of range (%d-%d)", c.ZoneSizeMB, minZoneMB, maxZoneMB)
	}
	return nil
}

// DefaultCCConfig 是合理的默认 CC 参数(关闭状态)。
func DefaultCCConfig() CCConfig {
	return CCConfig{Enabled: false, RatePerSec: 10, Burst: 20, ConnPerIP: 20, ZoneSizeMB: 10}
}
