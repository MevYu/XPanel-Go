package alert

import (
	"fmt"
	"strconv"
)

// Settings 是 alert 模块的可配置项,可由 admin 经 PUT /settings 修改。
type Settings struct {
	// IntervalSec 是后台评估周期(秒):每隔多久采集一次指标并检查规则。
	IntervalSec int `json:"interval_sec"`
	// SilenceSec 是同一规则的静默期(秒):一次触发通知后,该规则在此窗口内不再重复发通知。
	SilenceSec int `json:"silence_sec"`
}

// DefaultSettings 返回出厂默认设置。
func DefaultSettings() Settings {
	return Settings{
		IntervalSec: 30,
		SilenceSec:  300,
	}
}

// Validate 校验设置取值范围。
func (s Settings) Validate() error {
	if s.IntervalSec < 5 || s.IntervalSec > 3600 {
		return fmt.Errorf("alert: interval_sec must be 5..3600")
	}
	if s.SilenceSec < 0 || s.SilenceSec > 86400 {
		return fmt.Errorf("alert: silence_sec must be 0..86400")
	}
	return nil
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func itoa(n int) string { return strconv.Itoa(n) }
