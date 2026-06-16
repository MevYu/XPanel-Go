package cron

import (
	"testing"
	"time"
)

func TestScheduleBuild(t *testing.T) {
	cases := []struct {
		name string
		s    Schedule
		want string
		err  bool
	}{
		{"raw ok", Schedule{Kind: schedRaw, Expr: "*/5 * * * *"}, "*/5 * * * *", false},
		{"raw bad", Schedule{Kind: schedRaw, Expr: "nope"}, "", true},
		{"every n", Schedule{Kind: schedEveryNMinutes, Minute: 10}, "*/10 * * * *", false},
		{"every n zero", Schedule{Kind: schedEveryNMinutes, Minute: 0}, "", true},
		{"every n too big", Schedule{Kind: schedEveryNMinutes, Minute: 60}, "", true},
		{"hourly at", Schedule{Kind: schedHourlyAt, Minute: 30}, "30 * * * *", false},
		{"daily at", Schedule{Kind: schedDailyAt, Hour: 3, Minute: 15}, "15 3 * * *", false},
		{"daily bad hour", Schedule{Kind: schedDailyAt, Hour: 24, Minute: 0}, "", true},
		{"weekly at", Schedule{Kind: schedWeeklyAt, Weekday: 1, Hour: 9, Minute: 0}, "0 9 * * 1", false},
		{"weekly bad wd", Schedule{Kind: schedWeeklyAt, Weekday: 7, Hour: 9, Minute: 0}, "", true},
		{"monthly at", Schedule{Kind: schedMonthlyAt, Day: 1, Hour: 0, Minute: 0}, "0 0 1 * *", false},
		{"monthly bad day", Schedule{Kind: schedMonthlyAt, Day: 0, Hour: 0, Minute: 0}, "", true},
		{"unknown", Schedule{Kind: "wat"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.s.Build()
			if c.err {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
			if !ValidCronExpr(got) {
				t.Errorf("built expr %q does not validate", got)
			}
		})
	}
}

func TestParseCronRejects(t *testing.T) {
	bad := []string{
		"", "* * * *", "* * * * * *",
		"60 * * * *",  // minute out of range
		"* 24 * * *",  // hour out of range
		"* * 32 * *",  // dom out of range
		"* * * 13 *",  // month out of range
		"* * * * 8",   // dow out of range
		"5-1 * * * *", // reversed range
		"*/0 * * * *", // zero step
		"a * * * *",   // garbage
	}
	for _, b := range bad {
		if ValidCronExpr(b) {
			t.Errorf("expected %q to be invalid", b)
		}
	}
}

func TestParseCronNames(t *testing.T) {
	if !ValidCronExpr("0 0 * jan mon") {
		t.Error("month/dow names should parse")
	}
	if !ValidCronExpr("0 9 * * mon-fri") {
		t.Error("dow name range should parse")
	}
}

func TestCronMatches(t *testing.T) {
	// 2026-06-15 是周一。
	mon := time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC)
	cases := []struct {
		expr  string
		t     time.Time
		match bool
	}{
		{"30 9 * * *", mon, true},
		{"30 9 * * 1", mon, true},                     // 周一
		{"30 9 * * 2", mon, false},                    // 周二
		{"*/15 * * * *", mon, true},                   // 30 是 15 的倍数
		{"*/15 * * * *", mon.Add(time.Minute), false}, // 31 不是
		{"0 9 15 * *", mon, false},                    // 分钟不对
		{"30 9 15 * *", mon, true},                    // dom 命中 (AND, 因 dow=*)
		{"30 9 15 * 2", mon, true},                    // dom OR dow: dom 命中即可
		{"30 9 16 * 1", mon, true},                    // dom OR dow: dow 命中即可
		{"30 9 16 * 2", mon, false},                   // 两者都不中
	}
	for _, c := range cases {
		if got := CronMatches(c.expr, c.t); got != c.match {
			t.Errorf("CronMatches(%q, %v) = %v want %v", c.expr, c.t, got, c.match)
		}
	}
}
