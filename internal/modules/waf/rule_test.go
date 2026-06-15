package waf

import (
	"strings"
	"testing"
)

func TestIPRuleValidate(t *testing.T) {
	ok := []IPRule{
		{Action: "allow", CIDR: "1.2.3.4"},
		{Action: "deny", CIDR: "10.0.0.0/8"},
		{Action: "allow", CIDR: "2001:db8::1"},
		{Action: "deny", CIDR: "fe80::/10", Comment: "link local"},
	}
	for i, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("ok[%d] %+v rejected: %v", i, r, err)
		}
	}
	bad := []IPRule{
		{Action: "drop", CIDR: "1.2.3.4"},                  // bad action
		{Action: "allow", CIDR: "999.1.1.1"},               // bad ip
		{Action: "allow", CIDR: "10.0.0.0/99"},             // bad cidr
		{Action: "allow", CIDR: ""},                        // empty
		{Action: "allow", CIDR: "1.2.3.4; rm -rf /"},       // injection
		{Action: "allow", CIDR: "1.2.3.4", Comment: "a;b"}, // comment meta
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("bad[%d] %+v accepted", i, r)
		}
	}
}

func TestMatchRuleValidate(t *testing.T) {
	ok := []MatchRule{
		{Target: "uri", Pattern: `\.php`, Action: "block"},
		{Target: "ua", Pattern: `(?i)sqlmap`, Action: "block"},
		{Target: "uri", Pattern: `/admin`, Action: "allow"},
	}
	for i, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("ok[%d] %+v rejected: %v", i, r, err)
		}
	}
	bad := []MatchRule{
		{Target: "host", Pattern: "x", Action: "block"},                                 // bad target
		{Target: "uri", Pattern: "x", Action: "drop"},                                   // bad action
		{Target: "uri", Pattern: "", Action: "block"},                                   // empty pattern
		{Target: "uri", Pattern: "(", Action: "block"},                                  // invalid regex
		{Target: "ua", Pattern: "a**", Action: "block"},                                 // invalid regex repetition
		{Target: "uri", Pattern: `a"b`, Action: "block"},                                // quote escapes string
		{Target: "ua", Pattern: "a\nb", Action: "block"},                                // newline
		{Target: "uri", Pattern: "$host", Action: "block"},                              // nginx var injection
		{Target: "uri", Pattern: `bad\`, Action: "block"},                               // trailing backslash escapes quote
		{Target: "uri", Pattern: strings.Repeat("a", maxPatternLen+1), Action: "block"}, // too long
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("bad[%d] %+v accepted", i, r)
		}
	}

	// Patterns with regex metachars that are harmless inside a quoted nginx string
	// (and valid RE2) must be ACCEPTED — they only ever match request data, never execute.
	for _, p := range []string{`a\.php`, `\d{3}`, `foo|bar`, `(?i)admin`, `a;b`, `a#b`} {
		r := MatchRule{Target: "uri", Pattern: p, Action: "block"}
		if err := r.Validate(); err != nil {
			t.Errorf("safe pattern %q rejected: %v", p, err)
		}
	}
}

func TestCCConfigValidate(t *testing.T) {
	if err := (CCConfig{Enabled: false}).Validate(); err != nil {
		t.Errorf("disabled CC must skip threshold checks: %v", err)
	}
	if err := (CCConfig{Enabled: true, RatePerSec: 10, Burst: 20, ConnPerIP: 20, ZoneSizeMB: 10}).Validate(); err != nil {
		t.Errorf("valid CC rejected: %v", err)
	}
	bad := []CCConfig{
		{Enabled: true, RatePerSec: 0, ZoneSizeMB: 10},                 // rate too low
		{Enabled: true, RatePerSec: 999999, ZoneSizeMB: 10},            // rate too high
		{Enabled: true, RatePerSec: 10, Burst: -1, ZoneSizeMB: 10},     // neg burst
		{Enabled: true, RatePerSec: 10, ConnPerIP: -1, ZoneSizeMB: 10}, // neg conn
		{Enabled: true, RatePerSec: 10, ZoneSizeMB: 0},                 // zone too small
		{Enabled: true, RatePerSec: 10, ZoneSizeMB: 99999},             // zone too big
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("bad[%d] %+v accepted", i, c)
		}
	}
}

func TestHasNginxMeta(t *testing.T) {
	for _, s := range []string{"a;b", "a{b", "a}b", "a\nb", "a$b", "a\"b", "a#b", "a\\b"} {
		if !hasNginxMeta(s) {
			t.Errorf("%q should be flagged as meta", s)
		}
	}
	for _, s := range []string{"abc", `\.php$x`, "/admin/path", "sqlmap"} {
		// note: these contain no forbidden chars (".", "/", letters are fine)
		if strings.ContainsAny(s, nginxMetaChars) != hasNginxMeta(s) {
			t.Errorf("inconsistent meta detection for %q", s)
		}
	}
}
