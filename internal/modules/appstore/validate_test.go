package appstore

import (
	"strings"
	"testing"
)

func TestValidAppID(t *testing.T) {
	good := []string{"wordpress", "uptime-kuma", "n8n", "my_app1"}
	bad := []string{"", "-bad", "bad-", "Bad", "a/b", "a;b", "a b", "a\nb", strings.Repeat("a", 50), "..", "a$b"}
	for _, id := range good {
		if !validAppID(id) {
			t.Errorf("validAppID(%q) = false, want true", id)
		}
	}
	for _, id := range bad {
		if validAppID(id) {
			t.Errorf("validAppID(%q) = true, want false", id)
		}
	}
}

func TestValidInstanceName(t *testing.T) {
	if validInstanceName("../etc") || validInstanceName("a b") || validInstanceName("a\n") {
		t.Error("instance name whitelist must reject traversal/space/newline")
	}
	if !validInstanceName("wordpress-1") {
		t.Error("valid instance name rejected")
	}
}

func TestValidPort(t *testing.T) {
	for _, p := range []string{"1", "80", "65535"} {
		if !validPort(p) {
			t.Errorf("validPort(%q) want true", p)
		}
	}
	for _, p := range []string{"0", "65536", "-1", "abc", "80 ", "8080;rm", ""} {
		if validPort(p) {
			t.Errorf("validPort(%q) want false", p)
		}
	}
}

func TestValidPassword(t *testing.T) {
	if !validPassword("S3cret!_pass") {
		t.Error("good password rejected")
	}
	bad := []string{
		"short",                  // 太短
		"has space12",            // 空格
		"has\nnewline1",          // 换行
		"quote'inj12",            // 单引号(YAML 注入字符)
		"dollar$ign12",           // $
		"colon:inj123",           // : (YAML 键分隔)
		"back`tick123",           // 反引号
		`double"quote1`,          // 双引号
		strings.Repeat("a", 200), // 太长
	}
	for _, p := range bad {
		if validPassword(p) {
			t.Errorf("validPassword(%q) want false (injection/format)", p)
		}
	}
}

func TestValidAbsPath(t *testing.T) {
	if err := validAbsPath("/opt/xpanel/apps"); err != nil {
		t.Errorf("good path rejected: %v", err)
	}
	for _, p := range []string{"", "relative/path", "/a/../b", "/a/b/", "/a b", "/a;b", "/a$b", "/a\nb"} {
		if err := validAbsPath(p); err == nil {
			t.Errorf("validAbsPath(%q) want error", p)
		}
	}
}

func TestValidateParamsFillsDefaultsAndValidates(t *testing.T) {
	app, _ := LookupApp("postgres")
	// 用户只给端口与密码,db 走默认。
	out, err := validateParams(app, map[string]string{"port": "5433", "password": "S3cret!_pass"})
	if err != nil {
		t.Fatalf("validateParams: %v", err)
	}
	if out["port"] != "5433" || out["password"] != "S3cret!_pass" || out["db"] != "app" {
		t.Errorf("unexpected params: %v", out)
	}
}

func TestValidateParamsRejectsBadPort(t *testing.T) {
	app, _ := LookupApp("postgres")
	_, err := validateParams(app, map[string]string{"port": "99999", "password": "S3cret!_pass"})
	if err == nil {
		t.Error("bad port should be rejected")
	}
}

func TestValidateParamsRejectsInjectionPassword(t *testing.T) {
	app, _ := LookupApp("postgres")
	// 试图注入 YAML 结构的密码必须被拒。
	_, err := validateParams(app, map[string]string{"port": "5432", "password": "x'\n  evil: true"})
	if err == nil {
		t.Error("injection password must be rejected")
	}
}

func TestValidateParamsRejectsUnknownKey(t *testing.T) {
	app, _ := LookupApp("redis")
	_, err := validateParams(app, map[string]string{"port": "6379", "password": "S3cret!_pass", "extra": "x"})
	if err == nil {
		t.Error("unknown param key must be rejected")
	}
}

func TestValidateParamsRequiredMissing(t *testing.T) {
	app, _ := LookupApp("redis")
	// redis 密码必填且无默认。
	_, err := validateParams(app, map[string]string{"port": "6379"})
	if err == nil {
		t.Error("missing required password must be rejected")
	}
}
