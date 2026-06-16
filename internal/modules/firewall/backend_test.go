package firewall

import (
	"strings"
	"testing"
)

// fakeRunner 记录被执行的命令并按序返回预设结果。
type fakeRunner struct {
	calls   [][]string // 每次调用 [name, args...]
	results []string   // 与 calls 同序;不足则返回 ""
	idx     int
}

func (f *fakeRunner) run(name string, args []string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	out := ""
	if f.idx < len(f.results) {
		out = f.results[f.idx]
	}
	f.idx++
	return out, nil
}

func eqArgs(t *testing.T, got, want []string) {
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

// ---- ufw arg builders ----

func TestUFWPortArgs(t *testing.T) {
	b := &ufwBackend{}
	r := PortRule{Action: "allow", Port: "8000-9000", Proto: "tcp", Source: "10.0.0.0/8", Comment: "web"}
	eqArgs(t, b.portArgs(r, true), []string{"allow", "proto", "tcp", "from", "10.0.0.0/8", "to", "any", "port", "8000:9000", "comment", "web"})
	eqArgs(t, b.portArgs(r, false), []string{"delete", "allow", "proto", "tcp", "from", "10.0.0.0/8", "to", "any", "port", "8000:9000", "comment", "web"})

	any := PortRule{Action: "deny", Port: "22", Proto: "udp"}
	eqArgs(t, b.portArgs(any, true), []string{"deny", "proto", "udp", "from", "any", "to", "any", "port", "22"})
}

func TestUFWIPArgs(t *testing.T) {
	b := &ufwBackend{}
	eqArgs(t, b.ipArgs(IPRule{IPBlock, "1.2.3.4"}, true), []string{"deny", "from", "1.2.3.4"})
	eqArgs(t, b.ipArgs(IPRule{IPTrust, "10.0.0.0/8"}, true), []string{"allow", "from", "10.0.0.0/8"})
	eqArgs(t, b.ipArgs(IPRule{IPBlock, "1.2.3.4"}, false), []string{"delete", "deny", "from", "1.2.3.4"})
}

func TestUFWApplyUsesForce(t *testing.T) {
	fr := &fakeRunner{}
	b := &ufwBackend{run: fr}
	_, _ = b.ApplyPortRule(PortRule{Action: "allow", Port: "80", Proto: "tcp"}, true)
	if len(fr.calls) != 1 || fr.calls[0][0] != "ufw" || fr.calls[0][1] != "--force" {
		t.Errorf("ufw apply must prepend --force, got %v", fr.calls)
	}
}

func TestUFWPingUnsupported(t *testing.T) {
	b := &ufwBackend{run: &fakeRunner{}}
	if _, err := b.SetPing(true); err != errPingUnsupported {
		t.Errorf("ufw ping toggle must be unsupported, got %v", err)
	}
}

func TestUFWParseRules(t *testing.T) {
	out := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8000:9000/tcp              ALLOW IN    10.0.0.0/8                 # web range
[ 3] 53/udp                     DENY IN     1.2.3.4
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)`
	rules, _ := parseUFWRules(out)
	if len(rules) != 4 {
		t.Fatalf("want 4 rules, got %d: %+v", len(rules), rules)
	}
	if rules[1].Port != "8000-9000" || rules[1].Source != "10.0.0.0/8" || rules[1].Comment != "web range" {
		t.Errorf("range rule parsed wrong: %+v", rules[1])
	}
	if rules[2].Action != "deny" || rules[2].Proto != "udp" || rules[2].Source != "1.2.3.4" {
		t.Errorf("deny rule parsed wrong: %+v", rules[2])
	}
}

func TestUFWStatusRunning(t *testing.T) {
	fr := &fakeRunner{results: []string{"Status: active\n[ 1] 22/tcp ALLOW IN Anywhere"}}
	b := &ufwBackend{run: fr}
	st, err := b.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Backend != "ufw" || !st.Running || st.RuleCount != 1 {
		t.Errorf("unexpected status: %+v", st)
	}
}

// ---- firewalld arg builders ----

func TestFirewalldPortArgs(t *testing.T) {
	b := &firewalldBackend{}
	r := PortRule{Action: "allow", Port: "8000-9000", Proto: "tcp", Source: "192.168.0.0/16"}
	eqArgs(t, b.portArgs(r, true), []string{"--permanent", "--add-rich-rule=rule family=ipv4 source address=192.168.0.0/16 port port=8000-9000 protocol=tcp accept"})

	v6 := PortRule{Action: "deny", Port: "53", Proto: "udp", Source: "2001:db8::/32"}
	eqArgs(t, b.portArgs(v6, false), []string{"--permanent", "--remove-rich-rule=rule family=ipv6 source address=2001:db8::/32 port port=53 protocol=udp reject"})

	noSrc := PortRule{Action: "allow", Port: "80", Proto: "tcp"}
	eqArgs(t, b.portArgs(noSrc, true), []string{"--permanent", "--add-rich-rule=rule port port=80 protocol=tcp accept"})
}

func TestFirewalldIPArgs(t *testing.T) {
	b := &firewalldBackend{}
	eqArgs(t, b.ipArgs(IPRule{IPBlock, "1.2.3.4"}, true), []string{"--permanent", "--add-rich-rule=rule family=ipv4 source address=1.2.3.4 drop"})
	eqArgs(t, b.ipArgs(IPRule{IPTrust, "10.0.0.0/8"}, true), []string{"--permanent", "--add-rich-rule=rule family=ipv4 source address=10.0.0.0/8 accept"})
}

func TestFirewalldPingArgs(t *testing.T) {
	fr := &fakeRunner{}
	b := &firewalldBackend{run: fr}
	_, _ = b.SetPing(false) // block
	if fr.calls[0][2] != "--add-icmp-block=echo-request" {
		t.Errorf("block ping wrong: %v", fr.calls[0])
	}
	fr2 := &fakeRunner{}
	b2 := &firewalldBackend{run: fr2}
	_, _ = b2.SetPing(true) // allow
	if fr2.calls[0][2] != "--remove-icmp-block=echo-request" {
		t.Errorf("allow ping wrong: %v", fr2.calls[0])
	}
}

func TestFirewalldApplyReloads(t *testing.T) {
	fr := &fakeRunner{}
	b := &firewalldBackend{run: fr}
	_, _ = b.ApplyPortRule(PortRule{Action: "allow", Port: "80", Proto: "tcp"}, true)
	if len(fr.calls) != 2 {
		t.Fatalf("apply must reload (2 calls), got %d: %v", len(fr.calls), fr.calls)
	}
	last := fr.calls[1]
	if last[0] != "firewall-cmd" || last[1] != "--reload" {
		t.Errorf("second call must be reload, got %v", last)
	}
}

func TestFirewalldParseRules(t *testing.T) {
	out := `public (active)
  target: default
  ports: 22/tcp 8000-9000/udp 80/tcp
  rich rules:
	rule family="ipv4" source address="10.0.0.0/8" port port="443" protocol="tcp" accept
	rule family="ipv4" source address="9.9.9.9" drop`
	rules := parseFirewalldRules(out)
	// 3 from ports line + 1 port rich rule (the drop-only rule is a blacklist, not a port rule)
	if len(rules) != 4 {
		t.Fatalf("want 4 port rules, got %d: %+v", len(rules), rules)
	}
	var found bool
	for _, r := range rules {
		if r.Port == "8000-9000" && r.Proto == "udp" {
			found = true
		}
	}
	if !found {
		t.Errorf("range port not parsed: %+v", rules)
	}
	last := rules[len(rules)-1]
	if last.Port != "443" || last.Source != "10.0.0.0/8" {
		t.Errorf("rich rule parsed wrong: %+v", last)
	}
}

func TestRichAttr(t *testing.T) {
	line := `rule family="ipv4" source address="10.0.0.0/8" port port="443" protocol="tcp" accept`
	if got := richAttr(line, "source address="); got != "10.0.0.0/8" {
		t.Errorf("source: got %q", got)
	}
	if got := richAttr(line, "port port="); got != "443" {
		t.Errorf("port: got %q", got)
	}
	if got := richAttr(line, "missing="); got != "" {
		t.Errorf("missing should be empty, got %q", got)
	}
}

func TestDetectBackendNilWhenAbsent(t *testing.T) {
	// On a host with neither binary, detect returns nil. We can't guarantee
	// absence, so only assert the return is a known concrete type or nil.
	switch b := detectBackend(execRunner{}).(type) {
	case nil, *ufwBackend, *firewalldBackend:
	default:
		t.Errorf("unexpected backend type %T", b)
	}
}

func TestReadSSHPort(t *testing.T) {
	if p := readSSHPort("/nonexistent/sshd_config"); p != 22 {
		t.Errorf("missing config should default 22, got %d", p)
	}
	if p := readSSHPort("testdata/sshd_config"); p != 2222 {
		t.Errorf("configured Port 2222 should parse, got %d", p)
	}
}

func TestCmdErrorMessage(t *testing.T) {
	e := &cmdError{name: "ufw", args: []string{"status"}, err: errPingUnsupported}
	if !strings.Contains(e.Error(), "ufw status") {
		t.Errorf("cmdError should include command, got %q", e.Error())
	}
}
