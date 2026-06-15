package php

import (
	"strings"
	"testing"
)

const sampleIni = `[PHP]
; this is a comment
memory_limit = 128M
max_execution_time = 30
short_open_tag = Off

[Date]
date.timezone = UTC
`

func TestParseIniExtractsWhitelist(t *testing.T) {
	got := parseIni(sampleIni)
	if got["memory_limit"] != "128M" {
		t.Errorf("memory_limit = %q, want 128M", got["memory_limit"])
	}
	if got["date.timezone"] != "UTC" {
		t.Errorf("date.timezone = %q, want UTC", got["date.timezone"])
	}
	// 注释与 section 头不应混进结果。
	if _, ok := got["; this is a comment"]; ok {
		t.Error("comment leaked into parsed map")
	}
}

func TestApplyIniChangesInPlace(t *testing.T) {
	out := applyIniChanges(sampleIni, map[string]string{"memory_limit": "512M"})
	parsed := parseIni(out)
	if parsed["memory_limit"] != "512M" {
		t.Errorf("memory_limit = %q, want 512M", parsed["memory_limit"])
	}
	// 其它值与注释保留。
	if parsed["max_execution_time"] != "30" {
		t.Errorf("max_execution_time changed unexpectedly: %q", parsed["max_execution_time"])
	}
	if !strings.Contains(out, "; this is a comment") {
		t.Error("comment must be preserved")
	}
	// 不应重复 memory_limit 行。
	if strings.Count(out, "memory_limit") != 1 {
		t.Errorf("memory_limit appears %d times, want 1", strings.Count(out, "memory_limit"))
	}
}

func TestApplyIniChangesAppendsMissing(t *testing.T) {
	out := applyIniChanges(sampleIni, map[string]string{"post_max_size": "64M"})
	if parseIni(out)["post_max_size"] != "64M" {
		t.Error("missing key must be appended")
	}
}
