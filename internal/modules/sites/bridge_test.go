package sites

import (
	"strings"
	"testing"
)

func TestPHPSocketForVersion(t *testing.T) {
	set := testSettings()
	// 显式版本 → 版本化 sock 路径
	got, err := phpSocketFor("8.2", set)
	if err != nil {
		t.Fatalf("phpSocketFor: %v", err)
	}
	if got != "/run/php/php8.2-fpm.sock" {
		t.Errorf("phpSocketFor(8.2) = %q", got)
	}
	// 空版本 → 回退默认 socket
	got, err = phpSocketFor("", set)
	if err != nil || got != set.PHPSocket {
		t.Errorf("phpSocketFor(\"\") = (%q,%v), want default", got, err)
	}
	// 非法版本 → 错误
	if _, err := phpSocketFor("8.2;rm", set); err == nil {
		t.Error("phpSocketFor must reject invalid version")
	}
}

func TestSiteToConfigRoundTrip(t *testing.T) {
	set := testSettings()
	st := Site{
		Name:           "example.com",
		DomainBindings: []Domain{{"example.com", 80}},
		Kind:           "php",
		PHPVersion:     "8.2",
		RootDir:        "/www/wwwroot/example.com",
		IndexDocs:      []string{"index.php"},
		SSL:            SSL{Enabled: true, CertPath: "/c.pem", KeyPath: "/k.pem", ForceHTTPS: true},
		AccessLog:      "/www/wwwlogs/example.com.access.log",
		ErrorLog:       "/www/wwwlogs/example.com.error.log",
	}
	cfg, err := siteToConfig(st, set)
	if err != nil {
		t.Fatalf("siteToConfig: %v", err)
	}
	if cfg.PHPSocket != "/run/php/php8.2-fpm.sock" {
		t.Errorf("php socket not resolved: %q", cfg.PHPSocket)
	}
	out, err := generateConfig(cfg)
	if err != nil {
		t.Fatalf("generateConfig: %v", err)
	}
	if !strings.Contains(out, "listen 443 ssl;") || !strings.Contains(out, "fastcgi_pass") {
		t.Errorf("rendered config missing expected directives\n%s", out)
	}
}
