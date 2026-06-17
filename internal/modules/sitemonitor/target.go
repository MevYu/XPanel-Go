package sitemonitor

import (
	"fmt"
	"net/url"
	"strings"
)

// 探测目标的间隔/超时边界,挡住高频自打与永不超时。
const (
	minIntervalSec = 10
	maxIntervalSec = 86400
	minTimeoutSec  = 1
	maxTimeoutSec  = 60
	maxTargetName  = 64
	// maxResultsPerTarget 是每目标保留的探测历史条数;算可用率与裁剪用。
	maxResultsPerTarget = 100
)

// Target 是一个被主动探测的网站监控目标。
type Target struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	IntervalSec int    `json:"interval_sec"`
	TimeoutSec  int    `json:"timeout_sec"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   int64  `json:"created_at"`
}

// Result 是一次探测的结果记录。
type Result struct {
	ID         int64  `json:"id"`
	TargetID   int64  `json:"target_id"`
	CheckedAt  int64  `json:"checked_at"`
	Up         bool   `json:"up"`
	StatusCode int    `json:"status_code"` // 0 表示连接/超时失败,无 HTTP 响应
	LatencyMS  int64  `json:"latency_ms"`  // 请求耗时(毫秒)
	Err        string `json:"error,omitempty"`
}

// TargetView 是列表/详情返回:目标 + 最近探测摘要。
type TargetView struct {
	Target
	LastStatus    string  `json:"last_status"`     // "up" / "down" / "unknown"(尚无探测)
	LastCode      int     `json:"last_code"`       // 最近一次 HTTP 状态码
	LastLatencyMS int64   `json:"last_latency_ms"` // 最近一次响应时间
	LastCheckedAt int64   `json:"last_checked_at"` // 最近探测 Unix 秒;0 表示从未探测
	Availability  float64 `json:"availability"`    // 最近 N 条的 up 占比 0..1
}

// targetInput 是创建/更新目标的请求体。
type targetInput struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	IntervalSec int    `json:"interval_sec"`
	TimeoutSec  int    `json:"timeout_sec"`
	Enabled     bool   `json:"enabled"`
}

// validate 服务端白名单校验:名称非空且无控制字符,URL 仅 http/https 且 host 非空,
// 间隔/超时落在边界内。注意:此处只做语法校验,SSRF 的网段拦截在探测拨号时复核。
func (in targetInput) validate() error {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > maxTargetName {
		return fmt.Errorf("name must be 1..%d chars", maxTargetName)
	}
	if strings.ContainsAny(name, "\n\r\x00") {
		return fmt.Errorf("name must not contain control characters")
	}
	u, err := url.Parse(in.URL)
	if err != nil {
		return fmt.Errorf("url is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url must be http or https")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("url must have a host")
	}
	if in.IntervalSec < minIntervalSec || in.IntervalSec > maxIntervalSec {
		return fmt.Errorf("interval_sec must be %d..%d", minIntervalSec, maxIntervalSec)
	}
	if in.TimeoutSec < minTimeoutSec || in.TimeoutSec > maxTimeoutSec {
		return fmt.Errorf("timeout_sec must be %d..%d", minTimeoutSec, maxTimeoutSec)
	}
	return nil
}

// normalizedName 返回去除首尾空白后的名称。
func (in targetInput) normalizedName() string { return strings.TrimSpace(in.Name) }
