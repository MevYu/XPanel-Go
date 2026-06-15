package dns

import "testing"

func TestValidDomain(t *testing.T) {
	good := []string{"example.com", "sub.example.com", "a-b.example.org", "EXAMPLE.com", "example.com."}
	for _, d := range good {
		if !validDomain(d) {
			t.Errorf("validDomain(%q) = false, want true", d)
		}
	}
	bad := []string{
		"", "localhost", "com", ".com", "example.com;rndc",
		"exa mple.com", "-bad.com", "bad-.com", "ex\nample.com",
		"a..b.com", "$(reboot).com", "ex/ample.com",
	}
	for _, d := range bad {
		if validDomain(d) {
			t.Errorf("validDomain(%q) = true, want false (injection/malformed must be rejected)", d)
		}
	}
}

func TestValidRecordName(t *testing.T) {
	good := []string{"@", "www", "a.b", "*.dev", "_dmarc", "*"}
	for _, n := range good {
		if !validRecordName(n) {
			t.Errorf("validRecordName(%q) = false, want true", n)
		}
	}
	bad := []string{"", "www.*", "a.*.b", "bad name", "www;rm", "www\n", "../etc"}
	for _, n := range bad {
		if validRecordName(n) {
			t.Errorf("validRecordName(%q) = true, want false", n)
		}
	}
}

func TestValidType(t *testing.T) {
	for _, ty := range []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"} {
		if !validType(ty) {
			t.Errorf("validType(%q) = false, want true", ty)
		}
	}
	for _, ty := range []string{"a", "ANY", "AXFR", "", "A;DROP", "SOA"} {
		if validType(ty) {
			t.Errorf("validType(%q) = true, want false", ty)
		}
	}
}

func TestValidValueByType(t *testing.T) {
	cases := []struct {
		typ, val string
		want     bool
	}{
		{"A", "1.2.3.4", true},
		{"A", "::1", false},
		{"A", "1.2.3.4\nwww IN A 6.6.6.6", false}, // zone injection via newline
		{"A", "999.1.1.1", false},
		{"AAAA", "2001:db8::1", true},
		{"AAAA", "1.2.3.4", false},
		{"CNAME", "target.example.com", true},
		{"CNAME", "target.example.com.", true},
		{"CNAME", "bad target", false},
		{"CNAME", "evil.com\nINJECT", false},
		{"NS", "ns1.example.com", true},
		{"MX", "mail.example.com", true},
		{"TXT", "v=spf1 include:_spf.example.com ~all", true},
		{"TXT", "has\"quote", false},
		{"TXT", "has;semi", false},
		{"TXT", "line\nbreak", false},
		{"SRV", "5 5060 sip.example.com", true},
		{"SRV", "5 5060 .", true},
		{"SRV", "5 5060", false},
		{"CAA", `0 issue "letsencrypt.org"`, true},
		{"CAA", `0 evil "x"`, false},
		{"CAA", `0 issue letsencrypt.org`, false},
	}
	for _, c := range cases {
		if got := validValue(c.typ, c.val); got != c.want {
			t.Errorf("validValue(%q, %q) = %v, want %v", c.typ, c.val, got, c.want)
		}
	}
}

func TestValidValueRejectsControlChars(t *testing.T) {
	// 任何类型,含 NUL/CR/LF 都必须拒。
	for _, v := range []string{"x\x00y", "x\ry", "x\ny"} {
		for _, ty := range []string{"A", "TXT", "CNAME", "NS"} {
			if validValue(ty, v) {
				t.Errorf("validValue(%q, %q) accepted control char", ty, v)
			}
		}
	}
}

func TestTTLAndPriorityRange(t *testing.T) {
	if validTTL(59) || validTTL(604801) || !validTTL(300) {
		t.Error("TTL range check wrong")
	}
	if validPriority(-1) || validPriority(65536) || !validPriority(10) {
		t.Error("priority range check wrong")
	}
}
