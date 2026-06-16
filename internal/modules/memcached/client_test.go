package memcached

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseStats(t *testing.T) {
	raw := "STAT pid 1234\r\nSTAT uptime 3600\r\nSTAT version 1.6.21\r\nSTAT get_hits 80\r\nSTAT get_misses 20\r\nEND\r\n"
	out, err := parseStats(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("parseStats: %v", err)
	}
	if out["pid"] != "1234" || out["version"] != "1.6.21" || out["get_hits"] != "80" {
		t.Fatalf("unexpected parse result: %+v", out)
	}
	if len(out) != 5 {
		t.Fatalf("want 5 keys, got %d", len(out))
	}
}

func TestParseStatsError(t *testing.T) {
	for _, line := range []string{"ERROR\r\n", "CLIENT_ERROR bad command\r\n", "SERVER_ERROR out of memory\r\n"} {
		if _, err := parseStats(bufio.NewReader(strings.NewReader(line))); err == nil {
			t.Errorf("expected error for %q", strings.TrimSpace(line))
		}
	}
}

func TestParseStatsToleratesUnknownLines(t *testing.T) {
	raw := "garbage line\r\nSTAT pid 1\r\nNOTSTAT x y\r\nEND\r\n"
	out, err := parseStats(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("parseStats: %v", err)
	}
	if len(out) != 1 || out["pid"] != "1" {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestBuildStatsHitRate(t *testing.T) {
	raw := map[string]string{
		"get_hits": "75", "get_misses": "25",
		"bytes": "500", "limit_maxbytes": "1000",
		"curr_items": "10", "version": "1.6.0",
	}
	s := buildStats(raw)
	if s.HitRate != 0.75 {
		t.Errorf("hit_rate want 0.75, got %v", s.HitRate)
	}
	if s.MemUsageRate != 0.5 {
		t.Errorf("mem_usage_rate want 0.5, got %v", s.MemUsageRate)
	}
	if s.CurrItems != 10 || s.Version != "1.6.0" {
		t.Errorf("unexpected stats: %+v", s)
	}
}

func TestBuildStatsZeroGuards(t *testing.T) {
	// 无请求/无上限时派生率不能出现除零(应为 0)。
	s := buildStats(map[string]string{})
	if s.HitRate != 0 || s.MemUsageRate != 0 {
		t.Errorf("empty stats must yield 0 rates, got hit=%v mem=%v", s.HitRate, s.MemUsageRate)
	}
}

func TestGroupSlabs(t *testing.T) {
	flat := map[string]string{
		"1:chunk_size": "96", "1:chunks_per_page": "10922",
		"2:chunk_size": "120",
		"active_slabs": "2", "total_malloced": "1048576",
	}
	g := groupSlabs(flat)
	if g["1"]["chunk_size"] != "96" || g["2"]["chunk_size"] != "120" {
		t.Fatalf("slab classes mis-grouped: %+v", g)
	}
	if g["_global"]["active_slabs"] != "2" || g["_global"]["total_malloced"] != "1048576" {
		t.Fatalf("global slab fields mis-grouped: %+v", g["_global"])
	}
}
