package cron

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// 友好周期类型,前端选一个,后端落成 5 段 cron 表达式存库。
// 直接填表达式时 Kind 为 "raw"。
const (
	schedEveryNMinutes = "every_n_minutes" // 每 N 分钟: N=Minute
	schedHourlyAt      = "hourly_at"       // 每小时第 N 分: Minute
	schedDailyAt       = "daily_at"        // 每天 HH:MM: Hour/Minute
	schedWeeklyAt      = "weekly_at"       // 每周 Weekday 的 HH:MM: Weekday/Hour/Minute
	schedMonthlyAt     = "monthly_at"      // 每月 Day 的 HH:MM: Day/Hour/Minute
	schedRaw           = "raw"             // 直接给 Expr
)

// Schedule 描述任务何时运行。Kind=raw 时只用 Expr;其余用具体字段算出 Expr。
type Schedule struct {
	Kind    string `json:"kind"`
	Expr    string `json:"expr,omitempty"`    // raw 模式直接给;非 raw 由 Build 回填
	Minute  int    `json:"minute,omitempty"`  // 0-59;every_n_minutes 时表示 N(1-59)
	Hour    int    `json:"hour,omitempty"`    // 0-23
	Day     int    `json:"day,omitempty"`     // 1-31 (monthly_at)
	Weekday int    `json:"weekday,omitempty"` // 0-6, 0=周日 (weekly_at)
}

// Build 把友好周期编译成 5 段 cron 表达式;raw 模式校验并原样返回 Expr。
// 返回的表达式保证通过 system.ValidCronExpr。
func (s Schedule) Build() (string, error) {
	switch s.Kind {
	case schedRaw:
		expr := strings.TrimSpace(s.Expr)
		if !ValidCronExpr(expr) {
			return "", fmt.Errorf("invalid cron expression")
		}
		return expr, nil
	case schedEveryNMinutes:
		if s.Minute < 1 || s.Minute > 59 {
			return "", fmt.Errorf("every_n_minutes: minute must be 1-59")
		}
		return fmt.Sprintf("*/%d * * * *", s.Minute), nil
	case schedHourlyAt:
		if err := checkRange("minute", s.Minute, 0, 59); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d * * * *", s.Minute), nil
	case schedDailyAt:
		if err := s.checkHM(); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %d * * *", s.Minute, s.Hour), nil
	case schedWeeklyAt:
		if err := s.checkHM(); err != nil {
			return "", err
		}
		if err := checkRange("weekday", s.Weekday, 0, 6); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %d * * %d", s.Minute, s.Hour, s.Weekday), nil
	case schedMonthlyAt:
		if err := s.checkHM(); err != nil {
			return "", err
		}
		if err := checkRange("day", s.Day, 1, 31); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %d %d * *", s.Minute, s.Hour, s.Day), nil
	default:
		return "", fmt.Errorf("unknown schedule kind %q", s.Kind)
	}
}

func (s Schedule) checkHM() error {
	if err := checkRange("minute", s.Minute, 0, 59); err != nil {
		return err
	}
	return checkRange("hour", s.Hour, 0, 23)
}

func checkRange(name string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s must be %d-%d", name, lo, hi)
	}
	return nil
}

// ValidCronExpr 校验 5 段表达式并确保每段可被 matcher 解析(语义范围也校验)。
// 比 system.ValidCronExpr 更严:这里要真正用表达式匹配时间,必须保证可解析。
func ValidCronExpr(expr string) bool {
	_, err := parseCron(expr)
	return err == nil
}

// cronSpec 是解析后的 5 段表达式,每段是允许值集合。
type cronSpec struct {
	minute  map[int]bool // 0-59
	hour    map[int]bool // 0-23
	dom     map[int]bool // 1-31
	month   map[int]bool // 1-12
	dow     map[int]bool // 0-6 (0/7=周日,统一存 0)
	domStar bool         // dom 字段为 * (用于 dom/dow 的 OR 语义)
	dowStar bool         // dow 字段为 *
}

var monthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
var dowNames = map[string]int{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

// parseCron 解析 5 段标准 cron 表达式。支持 * , - / 与月/周名缩写。
func parseCron(expr string) (cronSpec, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return cronSpec{}, fmt.Errorf("cron: need 5 fields, got %d", len(fields))
	}
	var s cronSpec
	var err error
	if s.minute, err = parseField(fields[0], 0, 59, nil); err != nil {
		return cronSpec{}, fmt.Errorf("minute: %w", err)
	}
	if s.hour, err = parseField(fields[1], 0, 23, nil); err != nil {
		return cronSpec{}, fmt.Errorf("hour: %w", err)
	}
	if s.dom, err = parseField(fields[2], 1, 31, nil); err != nil {
		return cronSpec{}, fmt.Errorf("day-of-month: %w", err)
	}
	if s.month, err = parseField(fields[3], 1, 12, monthNames); err != nil {
		return cronSpec{}, fmt.Errorf("month: %w", err)
	}
	if s.dow, err = parseField(fields[4], 0, 7, dowNames); err != nil {
		return cronSpec{}, fmt.Errorf("day-of-week: %w", err)
	}
	// 把周日 7 归一成 0。
	if s.dow[7] {
		s.dow[0] = true
		delete(s.dow, 7)
	}
	s.domStar = strings.TrimSpace(fields[2]) == "*"
	s.dowStar = strings.TrimSpace(fields[4]) == "*"
	return s, nil
}

// parseField 解析单个字段为允许值集合。names 是该字段允许的名称缩写(可为 nil)。
func parseField(field string, lo, hi int, names map[string]int) (map[int]bool, error) {
	out := make(map[int]bool)
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty list element")
		}
		step := 1
		if slash := strings.IndexByte(part, '/'); slash >= 0 {
			st, err := strconv.Atoi(part[slash+1:])
			if err != nil || st < 1 {
				return nil, fmt.Errorf("invalid step %q", part[slash+1:])
			}
			step = st
			part = part[:slash]
		}
		rlo, rhi := lo, hi
		switch {
		case part == "*":
			// 全范围。
		case strings.IndexByte(part, '-') > 0:
			dash := strings.IndexByte(part, '-')
			a, err1 := atoiName(part[:dash], lo, hi, names)
			b, err2 := atoiName(part[dash+1:], lo, hi, names)
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			if a > b {
				return nil, fmt.Errorf("range start > end in %q", part)
			}
			rlo, rhi = a, b
		default:
			v, err := atoiName(part, lo, hi, names)
			if err != nil {
				return nil, err
			}
			rlo, rhi = v, v
		}
		for v := rlo; v <= rhi; v += step {
			out[v] = true
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no values")
	}
	return out, nil
}

func atoiName(s string, lo, hi int, names map[string]int) (int, error) {
	s = strings.TrimSpace(s)
	if names != nil {
		if v, ok := names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q", s)
	}
	if v < lo || v > hi {
		return 0, fmt.Errorf("value %d out of range %d-%d", v, lo, hi)
	}
	return v, nil
}

// matches 判断表达式是否在时刻 t 触发(分钟精度)。
// dom/dow 遵循 Vixie cron 语义:两者都非 * 时取 OR;否则取常规 AND。
func (s cronSpec) matches(t time.Time) bool {
	if !s.minute[t.Minute()] || !s.hour[t.Hour()] || !s.month[int(t.Month())] {
		return false
	}
	dom := s.dom[t.Day()]
	dow := s.dow[int(t.Weekday())]
	if !s.domStar && !s.dowStar {
		return dom || dow
	}
	return dom && dow
}

// CronMatches 是供模块调度用的便捷封装:解析失败视为不匹配。
func CronMatches(expr string, t time.Time) bool {
	spec, err := parseCron(expr)
	if err != nil {
		return false
	}
	return spec.matches(t)
}
