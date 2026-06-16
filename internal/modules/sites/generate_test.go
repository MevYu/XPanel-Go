package sites

import (
	"strings"
	"testing"
)

func baseStatic() SiteConfig {
	return SiteConfig{
		Name:      "example.com",
		Domains:   []Domain{{"example.com", 80}, {"www.example.com", 80}},
		Kind:      KindStatic,
		Root:      "/www/wwwroot/example.com",
		IndexDocs: []string{"index.html", "index.htm"},
		AccessLog: "/www/wwwlogs/example.com.access.log",
		ErrorLog:  "/www/wwwlogs/example.com.error.log",
	}
}

func mustGen(t *testing.T, c SiteConfig) string {
	t.Helper()
	out, err := generateConfig(c)
	if err != nil {
		t.Fatalf("generateConfig: %v", err)
	}
	return out
}

func TestGenStaticBasic(t *testing.T) {
	out := mustGen(t, baseStatic())
	for _, want := range []string{
		"listen 80;",
		"server_name example.com www.example.com;",
		"root /www/wwwroot/example.com;",
		"index index.html index.htm;",
		"access_log /www/wwwlogs/example.com.access.log;",
		"try_files",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("static config missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "fastcgi_pass") || strings.Contains(out, "proxy_pass") {
		t.Errorf("static must not contain php/proxy\n%s", out)
	}
}

func TestGenPHP(t *testing.T) {
	c := baseStatic()
	c.Kind = KindPHP
	c.PHPVersion = "8.2"
	c.PHPSocket = "/run/php/php8.2-fpm.sock"
	c.IndexDocs = []string{"index.php", "index.html"}
	out := mustGen(t, c)
	for _, want := range []string{
		"fastcgi_pass unix:/run/php/php8.2-fpm.sock;",
		"location ~ [.]php$ {",
		"index index.php index.html;",
		"SCRIPT_FILENAME",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("php config missing %q\n%s", want, out)
		}
	}
}

func TestGenProxy(t *testing.T) {
	c := SiteConfig{
		Name:      "api.example.com",
		Domains:   []Domain{{"api.example.com", 80}},
		Kind:      KindProxy,
		Upstream:  "http://127.0.0.1:3000",
		AccessLog: "/l/a.log", ErrorLog: "/l/e.log",
	}
	out := mustGen(t, c)
	for _, want := range []string{
		"proxy_pass http://127.0.0.1:3000;",
		"proxy_set_header Host $host;",
		"proxy_set_header X-Forwarded-For",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("proxy config missing %q\n%s", want, out)
		}
	}
}

func TestGenSSLDualBlock(t *testing.T) {
	c := baseStatic()
	c.SSL = SSL{Enabled: true, CertPath: "/ssl/example.com/fullchain.pem", KeyPath: "/ssl/example.com/key.pem", ForceHTTPS: true, HSTS: true}
	out := mustGen(t, c)
	// 必须有两个 server 块
	if strings.Count(out, "server {") < 2 {
		t.Errorf("ssl config must emit two server blocks\n%s", out)
	}
	for _, want := range []string{
		"listen 443 ssl;",
		"ssl_certificate /ssl/example.com/fullchain.pem;",
		"ssl_certificate_key /ssl/example.com/key.pem;",
		"return 301 https://$host$request_uri;", // force https 跳转
		"Strict-Transport-Security",             // hsts
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ssl config missing %q\n%s", want, out)
		}
	}
}

func TestGenSSLNoForceKeeps80Serving(t *testing.T) {
	c := baseStatic()
	c.SSL = SSL{Enabled: true, CertPath: "/c.pem", KeyPath: "/k.pem", ForceHTTPS: false}
	out := mustGen(t, c)
	// 不强制跳转时 80 块仍应提供 root,而非 301
	if strings.Contains(out, "return 301 https://") {
		t.Errorf("non-force-https should not 301\n%s", out)
	}
	if !strings.Contains(out, "listen 443 ssl;") {
		t.Errorf("ssl block missing\n%s", out)
	}
}

func TestGenRewrite(t *testing.T) {
	c := baseStatic()
	c.RewriteRules = "location / {\n    try_files $uri $uri/ /index.php?$args;\n}"
	out := mustGen(t, c)
	if !strings.Contains(out, "try_files $uri $uri/ /index.php?$args;") {
		t.Errorf("rewrite rules not embedded\n%s", out)
	}
}

func TestGenDirProtect(t *testing.T) {
	c := baseStatic()
	c.HtpasswdDir = "/etc/nginx/htpasswd"
	c.DirProtect = []DirProtect{{Path: "/admin", Username: "admin", PassHash: "$apr1$x$y"}}
	out := mustGen(t, c)
	for _, want := range []string{
		"location /admin {",
		`auth_basic "Restricted";`,
		"auth_basic_user_file /etc/nginx/htpasswd/example.com.htpasswd;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dir-protect config missing %q\n%s", want, out)
		}
	}
}

func TestGenRedirects(t *testing.T) {
	c := baseStatic()
	c.Redirects = []Redirect{
		{From: "/old", To: "https://example.com/new", Code: 301},
		{From: "/tmp", To: "/perm", Code: 302},
	}
	out := mustGen(t, c)
	for _, want := range []string{
		"location /old {",
		"return 301 https://example.com/new;",
		"location /tmp {",
		"return 302 /perm;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("redirect config missing %q\n%s", want, out)
		}
	}
}

func TestGenAntiLeech(t *testing.T) {
	c := baseStatic()
	c.AntiLeech = AntiLeech{Enabled: true, Extensions: []string{"jpg", "png", "mp4"}, AllowedReferers: []string{"example.com", "*.example.com"}}
	out := mustGen(t, c)
	for _, want := range []string{
		"location ~* [.](jpg|png|mp4)$ {",
		"valid_referers none blocked example.com *.example.com;",
		"if ($invalid_referer) {",
		"return 403;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("anti-leech config missing %q\n%s", want, out)
		}
	}
}

func TestGenCustomConfig(t *testing.T) {
	c := baseStatic()
	c.CustomConfig = "add_header X-Custom test;"
	out := mustGen(t, c)
	if !strings.Contains(out, "add_header X-Custom test;") {
		t.Errorf("custom config not appended\n%s", out)
	}
}

// 注入兜底:即便结构体被绕过校验塞入换行,生成必须拒绝。
func TestGenRejectsInjection(t *testing.T) {
	c := baseStatic()
	c.Root = "/www/x\nlocation / { root /etc; }"
	if _, err := generateConfig(c); err == nil {
		t.Error("generateConfig must reject control chars in root")
	}

	c = baseStatic()
	c.Domains = []Domain{{"a.com\nserver_name evil;", 80}}
	if _, err := generateConfig(c); err == nil {
		t.Error("generateConfig must reject control chars in domain")
	}

	c = baseStatic()
	c.AntiLeech = AntiLeech{Enabled: true, Extensions: []string{"jpg\n) { deny all; }"}, AllowedReferers: []string{"a.com"}}
	if _, err := generateConfig(c); err == nil {
		t.Error("generateConfig must reject bad extension")
	}
}

func TestGenFullCombo(t *testing.T) {
	c := baseStatic()
	c.Kind = KindPHP
	c.PHPSocket = "/run/php/php8.2-fpm.sock"
	c.PHPVersion = "8.2"
	c.IndexDocs = []string{"index.php"}
	c.SSL = SSL{Enabled: true, CertPath: "/c.pem", KeyPath: "/k.pem", ForceHTTPS: true, HSTS: true}
	c.RewriteRules = "location / { try_files $uri $uri/ /index.php?$args; }"
	c.HtpasswdDir = "/h"
	c.DirProtect = []DirProtect{{Path: "/wp-admin", Username: "a", PassHash: "$apr1$x$y"}}
	c.Redirects = []Redirect{{From: "/old", To: "/new", Code: 301}}
	c.AntiLeech = AntiLeech{Enabled: true, Extensions: []string{"jpg"}, AllowedReferers: []string{"example.com"}}
	c.CustomConfig = "client_max_body_size 64m;"
	out := mustGen(t, c)
	// 关键片段都应在 443 块内出现
	for _, want := range []string{"fastcgi_pass", "ssl_certificate", "wp-admin", "valid_referers", "client_max_body_size 64m;", "return 301 https://"} {
		if !strings.Contains(out, want) {
			t.Errorf("full combo missing %q\n%s", want, out)
		}
	}
}
