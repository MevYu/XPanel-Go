package ssl

import (
	"strings"
	"testing"
)

func TestValidDomainAcceptsNormal(t *testing.T) {
	good := []string{
		"example.com", "sub.example.com", "a.b.c.example.org",
		"*.example.com", "xn--p1ai.example.com", "EXAMPLE.com",
	}
	for _, d := range good {
		if !ValidDomain(d) {
			t.Errorf("ValidDomain(%q) = false, want true", d)
		}
	}
}

func TestValidDomainRejectsInjection(t *testing.T) {
	bad := []string{
		"", "example.com; rm -rf /", "example.com && curl evil",
		"a.com | nc", "$(whoami).com", "`id`.com", "ex ample.com",
		"-d evil.com", "--standalone", "a.com\nb.com", "*.*.com",
		"*example.com", "foo.*.com", "a..com", ".com", "com",
		"http://example.com", "example.com/", "exa<b>mple.com",
		strings.Repeat("a", 300) + ".com",
	}
	for _, d := range bad {
		if ValidDomain(d) {
			t.Errorf("ValidDomain(%q) = true, want false (injection/malformed)", d)
		}
	}
}

func TestValidDomainsRejectsEmptyAndBadMember(t *testing.T) {
	if ValidDomains(nil) {
		t.Error("empty list must be invalid")
	}
	if ValidDomains([]string{"ok.com", "bad;rm.com"}) {
		t.Error("list with one bad member must be invalid")
	}
	if !ValidDomains([]string{"a.com", "b.com"}) {
		t.Error("all-good list must be valid")
	}
}

// recordingRunner 记录传给 CLI 的精确参数,断言绝不含 shell 元字符拼接。
func TestCliIssueUsesArgArrayNoShell(t *testing.T) {
	var gotArgs []string
	c := &cliACME{backend: "acme.sh", run: func(name string, args ...string) (string, error) {
		gotArgs = append(gotArgs, args...)
		return "", nil
	}}
	err := c.Issue(IssueRequest{
		Domains: []string{"example.com"}, Challenge: ChallengeWebroot,
		Webroot: "/www/wwwroot", KeyPath: "/k", CertPath: "/c",
	})
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	// 域名作为独立 arg 出现,未被拼进其它字符串。
	found := false
	for _, a := range gotArgs {
		if a == "example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("domain must appear as a discrete arg, got %v", gotArgs)
	}
}

func TestCliIssueRejectsBadDomainBeforeExec(t *testing.T) {
	called := false
	c := &cliACME{backend: "acme.sh", run: func(string, ...string) (string, error) {
		called = true
		return "", nil
	}}
	err := c.Issue(IssueRequest{
		Domains: []string{"evil.com; rm -rf /"}, Challenge: ChallengeStandalone,
	})
	if err == nil {
		t.Error("Issue with injection domain must error")
	}
	if called {
		t.Error("runner must not be invoked for invalid domain")
	}
}

func TestCliWebrootRequiresWebroot(t *testing.T) {
	c := &cliACME{backend: "acme.sh", run: func(string, ...string) (string, error) { return "", nil }}
	err := c.Issue(IssueRequest{Domains: []string{"a.com"}, Challenge: ChallengeWebroot})
	if err == nil {
		t.Error("webroot challenge without webroot must error")
	}
}

func TestDetectACMEPrefersAcmeSh(t *testing.T) {
	lp := func(name string) (string, error) {
		return "/usr/bin/" + name, nil // both present
	}
	a, err := detectACME(lp, nil)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if a.Name() != "acme.sh" {
		t.Errorf("must prefer acme.sh, got %s", a.Name())
	}
}

func TestDetectACMEFallsBackCertbot(t *testing.T) {
	lp := func(name string) (string, error) {
		if name == "certbot" {
			return "/usr/bin/certbot", nil
		}
		return "", errNotFound
	}
	a, err := detectACME(lp, nil)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if a.Name() != "certbot" {
		t.Errorf("must fall back to certbot, got %s", a.Name())
	}
}

func TestDetectACMENoneErrors(t *testing.T) {
	lp := func(string) (string, error) { return "", errNotFound }
	if _, err := detectACME(lp, nil); err == nil {
		t.Error("no client present must error")
	}
}

var errNotFound = &lookupErr{}

type lookupErr struct{}

func (*lookupErr) Error() string { return "not found" }
