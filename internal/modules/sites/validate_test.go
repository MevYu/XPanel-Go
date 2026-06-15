package sites

import "testing"

func TestValidDomain(t *testing.T) {
	good := []string{"example.com", "a.b.example.com", "*.example.com", "x-y.co", "sub.example.io"}
	for _, d := range good {
		if !validDomain(d) {
			t.Errorf("validDomain(%q) = false, want true", d)
		}
	}
	bad := []string{
		"", "EXAMPLE.com", "example", "-bad.com", "bad-.com",
		"exa mple.com",
		"a.com\nserver_name evil;", // 换行注入
		"a.com\r",
		"a.com;rm -rf", "*.*.com", "a..com", "a.com/",
		"http://a.com", "a.com:80",
	}
	for _, d := range bad {
		if validDomain(d) {
			t.Errorf("validDomain(%q) = true, want false", d)
		}
	}
}

func TestValidDomainsList(t *testing.T) {
	if err := validDomains(nil); err == nil {
		t.Error("empty domain list must error")
	}
	if err := validDomains([]string{"a.com", "a.com"}); err == nil {
		t.Error("duplicate domains must error")
	}
	if err := validDomains([]string{"a.com", "bad_domain"}); err == nil {
		t.Error("list with invalid domain must error")
	}
	if err := validDomains([]string{"a.com", "b.com"}); err != nil {
		t.Errorf("valid list errored: %v", err)
	}
}

func TestValidUpstream(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"http://127.0.0.1:3000", "http://127.0.0.1:3000", true},
		{"https://backend.local:8443", "https://backend.local:8443", true},
		{"http://APP.LOCAL:80", "http://app.local:80", true},
		{"ftp://x:21", "", false},
		{"http://x", "", false},                      // 缺端口
		{"http://x:99999", "", false},                // 端口越界
		{"http://x:80/path", "", false},              // 含路径
		{"http://x:80\nproxy_pass evil;", "", false}, // 换行注入
		{"http://x:80;rm", "", false},                // shell 元字符
		{"http://x:80 extra", "", false},             // 空格
		{"127.0.0.1:3000", "", false},                // 缺 scheme
	}
	for _, c := range cases {
		got, err := validUpstream(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("validUpstream(%q) = (%q,%v), want (%q,nil)", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("validUpstream(%q) = (%q,nil), want error", c.in, got)
		}
	}
}

func TestValidPHPSock(t *testing.T) {
	if err := validPHPSock("/run/php/php8.2-fpm.sock"); err != nil {
		t.Errorf("valid sock errored: %v", err)
	}
	bad := []string{"127.0.0.1:9000", "/run/php.sock\nx", "relative.sock", "/run/../etc.sock", "/run/php.txt"}
	for _, s := range bad {
		if err := validPHPSock(s); err == nil {
			t.Errorf("validPHPSock(%q) should error", s)
		}
	}
}

func TestSafeWebRoot(t *testing.T) {
	base := "/www/wwwroot"
	got, err := safeWebRoot(base, "example.com")
	if err != nil || got != "/www/wwwroot/example.com" {
		t.Errorf("safeWebRoot ok case = (%q,%v)", got, err)
	}
	for _, name := range []string{"../etc", "a/../../b", "..", "bad name", "a/b"} {
		if _, err := safeWebRoot(base, name); err == nil {
			t.Errorf("safeWebRoot(%q) should error", name)
		}
	}
}

func TestValidSiteName(t *testing.T) {
	if !validSiteName("example.com") {
		t.Error("example.com should be a valid site name")
	}
	for _, n := range []string{"", "../x", "a b", "a/b", "a\nb", ".."} {
		if validSiteName(n) {
			t.Errorf("validSiteName(%q) = true, want false", n)
		}
	}
}
