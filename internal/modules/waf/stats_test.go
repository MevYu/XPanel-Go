package waf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadStatsMissingFile(t *testing.T) {
	s, err := ReadStats(filepath.Join(t.TempDir(), "nope.log"))
	if err != nil {
		t.Fatalf("missing log must not error: %v", err)
	}
	if s.LogExists || s.Total != 0 || s.Blocked != 0 || s.Limited != 0 {
		t.Errorf("missing log should yield zero stats, got %+v", s)
	}
}

func TestReadStatsCounts(t *testing.T) {
	log := `1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.1" 200 612 "-" "curl"
1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /evil HTTP/1.1" 403 0 "-" "sqlmap"
1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.1" 444 0 "-" "bad"
1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /y HTTP/1.1" 503 0 "-" "flood"
1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /z HTTP/1.1" 429 0 "-" "flood"
this is a malformed line that should be skipped
`
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := ReadStats(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !s.LogExists {
		t.Error("log_exists should be true")
	}
	if s.Total != 5 {
		t.Errorf("total = %d, want 5 (malformed skipped)", s.Total)
	}
	if s.Blocked != 2 {
		t.Errorf("blocked = %d, want 2 (403+444)", s.Blocked)
	}
	if s.Limited != 2 {
		t.Errorf("limited = %d, want 2 (503+429)", s.Limited)
	}
}
