package firewall

import (
	"strings"
	"testing"
)

func TestValidPort(t *testing.T) {
	for _, p := range []int{1, 22, 80, 65535} {
		if !validPort(p) {
			t.Errorf("port %d should be valid", p)
		}
	}
	for _, p := range []int{0, -1, 65536} {
		if validPort(p) {
			t.Errorf("port %d should be invalid", p)
		}
	}
}

func TestValidProto(t *testing.T) {
	for _, p := range []string{"tcp", "udp"} {
		if !validProto(p) {
			t.Errorf("proto %q should be valid", p)
		}
	}
	for _, p := range []string{"", "TCP", "icmp", "tcp;rm"} {
		if validProto(p) {
			t.Errorf("proto %q should be invalid", p)
		}
	}
}

func TestValidSource(t *testing.T) {
	for _, s := range []string{"", "192.168.1.1", "10.0.0.0/8", "2001:db8::1", "fe80::/10"} {
		if !validSource(s) {
			t.Errorf("source %q should be valid", s)
		}
	}
	for _, s := range []string{"999.1.1.1", "10.0.0.0/99", "1.2.3.4; rm -rf", "notanip", "/24"} {
		if validSource(s) {
			t.Errorf("source %q should be invalid", s)
		}
	}
}

func TestValidIP(t *testing.T) {
	// empty is NOT valid for blacklist/whitelist entries.
	if validIP("") {
		t.Error("empty ip must be invalid for ip rules")
	}
	for _, s := range []string{"1.2.3.4", "10.0.0.0/8", "2001:db8::/32"} {
		if !validIP(s) {
			t.Errorf("ip %q should be valid", s)
		}
	}
	for _, s := range []string{"bad", "1.2.3.4; x", "300.1.1.1"} {
		if validIP(s) {
			t.Errorf("ip %q should be invalid", s)
		}
	}
}

func TestValidComment(t *testing.T) {
	if !validComment("") || !validComment("web server 8080") {
		t.Error("plain comments should be valid")
	}
	if validComment("a\nb") || validComment("x\ty\x00") {
		t.Error("control chars must be rejected")
	}
	if validComment(strings.Repeat("a", maxComment+1)) {
		t.Error("over-long comment must be rejected")
	}
}

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		in            string
		from, to      int
		isRange, fail bool
	}{
		{"80", 80, 80, false, false},
		{"1", 1, 1, false, false},
		{"65535", 65535, 65535, false, false},
		{"8000-9000", 8000, 9000, true, false},
		{"100-100", 100, 100, false, false}, // collapses to single
		{"0", 0, 0, false, true},
		{"70000", 0, 0, false, true},
		{"9000-8000", 0, 0, false, true}, // from>to
		{"80-", 0, 0, false, true},
		{"-80", 0, 0, false, true},
		{"1-2-3", 0, 0, false, true},
		{"", 0, 0, false, true},
		{"abc", 0, 0, false, true},
	}
	for _, c := range cases {
		from, to, isRange, err := parsePortSpec(c.in)
		if c.fail {
			if err == nil {
				t.Errorf("%q should fail", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q unexpected err: %v", c.in, err)
			continue
		}
		if from != c.from || to != c.to || isRange != c.isRange {
			t.Errorf("%q got (%d,%d,%v) want (%d,%d,%v)", c.in, from, to, isRange, c.from, c.to, c.isRange)
		}
	}
}

func TestPortRuleValidate(t *testing.T) {
	ok := PortRule{Action: "allow", Port: "8000-9000", Proto: "tcp", Source: "10.0.0.0/8", Comment: "x"}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid rule rejected: %v", err)
	}
	bad := []PortRule{
		{Action: "drop", Port: "80", Proto: "tcp"},
		{Action: "allow", Port: "0", Proto: "tcp"},
		{Action: "allow", Port: "9000-8000", Proto: "tcp"},
		{Action: "allow", Port: "80", Proto: "icmp"},
		{Action: "allow", Port: "80", Proto: "tcp", Source: "bad"},
		{Action: "allow", Port: "80", Proto: "tcp", Comment: "a\nb"},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d invalid rule accepted: %+v", i, c)
		}
	}
}

func TestIPRuleValidate(t *testing.T) {
	for _, r := range []IPRule{{IPBlock, "1.2.3.4"}, {IPTrust, "10.0.0.0/8"}} {
		if err := r.Validate(); err != nil {
			t.Errorf("valid ip rule rejected: %+v %v", r, err)
		}
	}
	for _, r := range []IPRule{{"nuke", "1.2.3.4"}, {IPBlock, ""}, {IPTrust, "bad"}} {
		if err := r.Validate(); err == nil {
			t.Errorf("invalid ip rule accepted: %+v", r)
		}
	}
}
