package system

import "testing"

func TestValidPort(t *testing.T) {
	ok := []int{1, 22, 80, 443, 65535}
	for _, p := range ok {
		if !ValidPort(p) {
			t.Errorf("port %d should be valid", p)
		}
	}
	bad := []int{0, -1, 65536, 100000}
	for _, p := range bad {
		if ValidPort(p) {
			t.Errorf("port %d should be invalid", p)
		}
	}
}

func TestValidProto(t *testing.T) {
	for _, p := range []string{"tcp", "udp"} {
		if !ValidProto(p) {
			t.Errorf("proto %q should be valid", p)
		}
	}
	for _, p := range []string{"", "TCP", "icmp", "tcp;rm", "sctp"} {
		if ValidProto(p) {
			t.Errorf("proto %q should be invalid", p)
		}
	}
}

func TestValidSource(t *testing.T) {
	// empty source means "any" and is allowed.
	for _, s := range []string{"", "192.168.1.1", "10.0.0.0/8", "2001:db8::1", "fe80::/10"} {
		if !ValidSource(s) {
			t.Errorf("source %q should be valid", s)
		}
	}
	for _, s := range []string{"999.1.1.1", "10.0.0.0/99", "1.2.3.4; rm -rf", "notanip", "192.168.1.0/", "/24"} {
		if ValidSource(s) {
			t.Errorf("source %q should be invalid", s)
		}
	}
}

func TestFirewallRuleValidate(t *testing.T) {
	valid := FirewallRule{Action: "allow", Port: 80, Proto: "tcp", Source: "10.0.0.0/8"}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid rule rejected: %v", err)
	}
	cases := []FirewallRule{
		{Action: "drop", Port: 80, Proto: "tcp"},                 // bad action
		{Action: "allow", Port: 0, Proto: "tcp"},                 // bad port
		{Action: "allow", Port: 80, Proto: "icmp"},               // bad proto
		{Action: "allow", Port: 80, Proto: "tcp", Source: "bad"}, // bad source
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: invalid rule accepted: %+v", i, c)
		}
	}
}

func TestDetectBackendType(t *testing.T) {
	// The test host may have any backend or none; only assert a known value.
	switch DetectBackend() {
	case BackendUFW, BackendFirewalld, BackendNone:
	default:
		t.Errorf("unexpected backend %q", DetectBackend())
	}
}

func TestFirewallAvailableMatchesDetect(t *testing.T) {
	err := FirewallAvailable()
	if DetectBackend() == BackendNone && err == nil {
		t.Error("FirewallAvailable must fail when no backend detected")
	}
	if DetectBackend() != BackendNone && err != nil {
		t.Errorf("FirewallAvailable must succeed when backend present, got %v", err)
	}
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len mismatch:\n got=%v\nwant=%v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("arg %d mismatch:\n got=%v\nwant=%v", i, got, want)
		}
	}
}

func TestUFWArgs(t *testing.T) {
	r := FirewallRule{Action: "allow", Port: 80, Proto: "tcp", Source: "10.0.0.0/8"}
	eq(t, r.ufwArgs(true), []string{"allow", "proto", "tcp", "from", "10.0.0.0/8", "to", "any", "port", "80"})
	eq(t, r.ufwArgs(false), []string{"delete", "allow", "proto", "tcp", "from", "10.0.0.0/8", "to", "any", "port", "80"})

	any := FirewallRule{Action: "deny", Port: 22, Proto: "udp"}
	eq(t, any.ufwArgs(true), []string{"deny", "proto", "udp", "from", "any", "to", "any", "port", "22"})
}

func TestFirewalldArgs(t *testing.T) {
	r := FirewallRule{Action: "allow", Port: 443, Proto: "tcp", Source: "192.168.0.0/16"}
	eq(t, r.firewalldArgs(true), []string{"--permanent", "--add-rich-rule=rule family=ipv4 source address=192.168.0.0/16 port port=443 protocol=tcp accept"})
	eq(t, r.firewalldArgs(false), []string{"--permanent", "--remove-rich-rule=rule family=ipv4 source address=192.168.0.0/16 port port=443 protocol=tcp accept"})

	v6 := FirewallRule{Action: "deny", Port: 53, Proto: "udp", Source: "2001:db8::/32"}
	eq(t, v6.firewalldArgs(true), []string{"--permanent", "--add-rich-rule=rule family=ipv6 source address=2001:db8::/32 port port=53 protocol=udp reject"})

	noSrc := FirewallRule{Action: "allow", Port: 80, Proto: "tcp"}
	eq(t, noSrc.firewalldArgs(true), []string{"--permanent", "--add-rich-rule=rule port port=80 protocol=tcp accept"})
}
