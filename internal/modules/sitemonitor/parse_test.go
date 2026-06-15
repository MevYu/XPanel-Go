package sitemonitor

import "testing"

func TestParseCombinedHappyPath(t *testing.T) {
	line := `192.168.1.10 - alice [10/Oct/2023:13:55:36 -0700] "GET /index.html?x=1 HTTP/1.1" 200 2326 "https://ref.example/" "Mozilla/5.0 (X11)"`
	e, ok := ParseCombined(line)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if e.IP != "192.168.1.10" {
		t.Errorf("ip = %q", e.IP)
	}
	if e.Method != "GET" || e.URL != "/index.html?x=1" {
		t.Errorf("request = %q %q", e.Method, e.URL)
	}
	if e.Status != 200 || e.Bytes != 2326 {
		t.Errorf("status/bytes = %d/%d", e.Status, e.Bytes)
	}
	if e.Referer != "https://ref.example/" {
		t.Errorf("referer = %q", e.Referer)
	}
	if e.UserAgent != "Mozilla/5.0 (X11)" {
		t.Errorf("ua = %q", e.UserAgent)
	}
	if e.Time.IsZero() {
		t.Error("time not parsed")
	}
	if y := e.Time.Year(); y != 2023 {
		t.Errorf("year = %d", y)
	}
}

func TestParseCombinedDashBytes(t *testing.T) {
	line := `10.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 304 - "-" "curl/8.0"`
	e, ok := ParseCombined(line)
	if !ok {
		t.Fatal("expected ok")
	}
	if e.Bytes != 0 {
		t.Errorf("dash bytes should be 0, got %d", e.Bytes)
	}
	if e.Status != 304 {
		t.Errorf("status = %d", e.Status)
	}
}

func TestParseCombinedEscapedQuoteInUA(t *testing.T) {
	line := `1.1.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /a HTTP/1.1" 200 5 "-" "weird \"agent\" v1"`
	e, ok := ParseCombined(line)
	if !ok {
		t.Fatal("expected ok")
	}
	if e.UserAgent != `weird "agent" v1` {
		t.Errorf("ua = %q", e.UserAgent)
	}
}

func TestParseCombinedRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"not a log line",
		`1.1.1.1 - - [bad time] "GET / HTTP/1.1" 200 5 "-" "-"`, // time bad but should still parse (best-effort) — keep separate
		`1.1.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" notanumber 5 "-" "-"`,
		`1.1.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200`, // truncated
	}
	for _, line := range bad {
		if _, ok := ParseCombined(line); ok && line != bad[2] {
			t.Errorf("expected reject for %q", line)
		}
	}
}

func TestParseCombinedBadTimeStillParses(t *testing.T) {
	// 时间畸形是 best-effort:其余字段有效则记录可用,Time 留零值。
	line := `1.1.1.1 - - [bad-time] "GET /x HTTP/1.1" 200 5 "-" "-"`
	e, ok := ParseCombined(line)
	if !ok {
		t.Fatal("expected ok with zero time")
	}
	if !e.Time.IsZero() {
		t.Error("expected zero time for bad timestamp")
	}
	if e.URL != "/x" {
		t.Errorf("url = %q", e.URL)
	}
}
