package sites

import "testing"

func TestValidPHPVersion(t *testing.T) {
	for _, v := range []string{"7.4", "8.0", "8.1", "8.2", "8.3", "5.6"} {
		if !validPHPVersion(v) {
			t.Errorf("validPHPVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "8", "8.2.1", "8.x", "8.2;rm", "8.2\n", "../8.2", "8 2"} {
		if validPHPVersion(v) {
			t.Errorf("validPHPVersion(%q) = true, want false", v)
		}
	}
}

func TestValidExtension(t *testing.T) {
	for _, e := range []string{"jpg", "png", "mp4", "webp", "JPG", "tar.gz"} {
		if !validExtension(e) {
			t.Errorf("validExtension(%q) = false, want true", e)
		}
	}
	for _, e := range []string{"", ".jpg", "jp g", "jpg;deny", "jpg\n", "a/b", "../x", "*"} {
		if validExtension(e) {
			t.Errorf("validExtension(%q) = true, want false", e)
		}
	}
}

func TestValidReferer(t *testing.T) {
	for _, r := range []string{"example.com", "*.example.com", "cdn.example.io", "none", "blocked"} {
		if !validReferer(r) {
			t.Errorf("validReferer(%q) = false, want true", r)
		}
	}
	for _, r := range []string{"", "exa mple.com", "a.com\nvalid_referers evil", "a.com;deny", "a.com/path", "http://a.com"} {
		if validReferer(r) {
			t.Errorf("validReferer(%q) = true, want false", r)
		}
	}
}

func TestValidBasicUsername(t *testing.T) {
	for _, u := range []string{"admin", "user1", "a.b_c-d"} {
		if !validBasicUsername(u) {
			t.Errorf("validBasicUsername(%q) = false, want true", u)
		}
	}
	for _, u := range []string{"", "a b", "a:b", "a\nb", "a;b", "root/x", "..", string(make([]byte, 65))} {
		if validBasicUsername(u) {
			t.Errorf("validBasicUsername(%q) = true, want false", u)
		}
	}
}

func TestValidLocationPath(t *testing.T) {
	for _, p := range []string{"/", "/admin", "/a/b", "/wp-admin", "/foo.bar"} {
		if err := validLocationPath(p); err != nil {
			t.Errorf("validLocationPath(%q) = %v, want nil", p, err)
		}
	}
	for _, p := range []string{"", "admin", "/a b", "/a;deny", "/a\n", "/a{", "/../etc", "/a..b"} {
		if err := validLocationPath(p); err == nil {
			t.Errorf("validLocationPath(%q) = nil, want error", p)
		}
	}
}

func TestValidRedirectTarget(t *testing.T) {
	for _, tgt := range []string{"https://example.com", "http://a.com/b", "/local/path", "https://x.com/a?b=c"} {
		if err := validRedirectTarget(tgt); err != nil {
			t.Errorf("validRedirectTarget(%q) = %v, want nil", tgt, err)
		}
	}
	for _, tgt := range []string{"", "javascript:alert(1)", "https://a.com\ndeny", "/a b", "ftp://x", "//evil", "a.com;rm"} {
		if err := validRedirectTarget(tgt); err == nil {
			t.Errorf("validRedirectTarget(%q) = nil, want error", tgt)
		}
	}
}

func TestValidRedirectCode(t *testing.T) {
	for _, c := range []int{301, 302} {
		if !validRedirectCode(c) {
			t.Errorf("validRedirectCode(%d) = false", c)
		}
	}
	for _, c := range []int{0, 200, 303, 307, 404} {
		if validRedirectCode(c) {
			t.Errorf("validRedirectCode(%d) = true", c)
		}
	}
}

func TestValidNginxFragment(t *testing.T) {
	// 合法的 rewrite / custom 片段(无危险注入字符)
	for _, frag := range []string{
		"rewrite ^/old$ /new permanent;",
		"location /api { proxy_pass http://127.0.0.1:9000; }",
		"add_header X-Frame-Options SAMEORIGIN;",
		"", // 空允许
	} {
		if err := validNginxFragment(frag); err != nil {
			t.Errorf("validNginxFragment(%q) = %v, want nil", frag, err)
		}
	}
	// 危险:NUL / 回车注入控制字符
	for _, frag := range []string{"a\x00b", "rewrite\r\n\x00 evil"} {
		if err := validNginxFragment(frag); err == nil {
			t.Errorf("validNginxFragment(%q) = nil, want error", frag)
		}
	}
}

func TestValidDomainPort(t *testing.T) {
	for _, d := range []Domain{{"example.com", 80}, {"a.example.com", 443}, {"x.io", 0}} {
		if err := validDomainBinding(d); err != nil {
			t.Errorf("validDomainBinding(%+v) = %v, want nil", d, err)
		}
	}
	for _, d := range []Domain{{"bad domain", 80}, {"a.com\nx", 80}, {"a.com", 70000}, {"a.com", -1}} {
		if err := validDomainBinding(d); err == nil {
			t.Errorf("validDomainBinding(%+v) = nil, want error", d)
		}
	}
}
