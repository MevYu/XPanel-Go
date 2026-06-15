package sites

import (
	"strings"
	"testing"
)

func testSettings() Settings {
	return Settings{
		WebRoot:   "/www/wwwroot",
		ConfDir:   "/etc/nginx/conf.d",
		LogDir:    "/www/wwwlogs",
		PHPSocket: "/run/php/php-fpm.sock",
	}
}

func TestRenderStatic(t *testing.T) {
	v, err := buildVHost(createRequest{
		Domains: []string{"example.com", "www.example.com"}, Kind: "static",
	}, testSettings())
	if err != nil {
		t.Fatalf("buildVHost: %v", err)
	}
	out, err := renderVHost(v)
	if err != nil {
		t.Fatalf("renderVHost: %v", err)
	}
	for _, want := range []string{
		"listen 80;",
		"server_name example.com www.example.com;",
		"root /www/wwwroot/example.com;",
		"try_files $uri $uri/ =404;",
		"access_log /www/wwwlogs/example.com.access.log;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("static config missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "proxy_pass") || strings.Contains(out, "fastcgi_pass") {
		t.Errorf("static config should not contain proxy/fastcgi\n%s", out)
	}
}

func TestRenderProxy(t *testing.T) {
	v, err := buildVHost(createRequest{
		Domains: []string{"api.example.com"}, Kind: "proxy", Upstream: "http://127.0.0.1:3000",
	}, testSettings())
	if err != nil {
		t.Fatalf("buildVHost: %v", err)
	}
	out, err := renderVHost(v)
	if err != nil {
		t.Fatalf("renderVHost: %v", err)
	}
	for _, want := range []string{
		"upstream xpanel_api.example.com {",
		"server 127.0.0.1:3000;",
		"proxy_pass http://127.0.0.1:3000;",
		"proxy_set_header Host $host;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("proxy config missing %q\n---\n%s", want, out)
		}
	}
}

func TestRenderPHP(t *testing.T) {
	v, err := buildVHost(createRequest{
		Domains: []string{"blog.example.com"}, Kind: "php", PHPSocket: "/run/php/php8.2-fpm.sock",
	}, testSettings())
	if err != nil {
		t.Fatalf("buildVHost: %v", err)
	}
	out, err := renderVHost(v)
	if err != nil {
		t.Fatalf("renderVHost: %v", err)
	}
	for _, want := range []string{
		"root /www/wwwroot/blog.example.com;",
		"index index.php index.html;",
		"fastcgi_pass unix:/run/php/php8.2-fpm.sock;",
		"location ~ \\.php$ {",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("php config missing %q\n---\n%s", want, out)
		}
	}
}

// 注入用例:恶意域名/upstream/socket 必须在 buildVHost 阶段被拒,绝不进入配置。
func TestBuildRejectsInjection(t *testing.T) {
	set := testSettings()
	bad := []createRequest{
		{Domains: []string{"a.com\nserver_name evil;"}, Kind: "static"},
		{Domains: []string{"a.com}\nlocation /{deny all;"}, Kind: "static"},
		{Domains: []string{"../../etc"}, Kind: "static"},
		{Domains: []string{"a.com"}, Kind: "proxy", Upstream: "http://x:80\nproxy_pass http://evil;"},
		{Domains: []string{"a.com"}, Kind: "proxy", Upstream: "http://x:80;injected"},
		{Domains: []string{"a.com"}, Kind: "php", PHPSocket: "/run/x.sock\nfastcgi_pass evil;"},
		{Domains: []string{"a.com"}, Kind: "php", PHPSocket: "127.0.0.1:9000"},
		{Domains: []string{"a.com"}, Kind: "static", Index: "index.html;deny"},
		{Domains: []string{"a.com"}, Kind: "evil"},
		{Domains: nil, Kind: "static"},
	}
	for i, req := range bad {
		if _, err := buildVHost(req, set); err == nil {
			t.Errorf("case %d: malicious request was accepted: %+v", i, req)
		}
	}
}

// assertNoInjection 兜底:即便有人绕过 buildVHost 塞入换行,渲染也必须拒绝。
func TestRenderRejectsRawInjection(t *testing.T) {
	v := VHost{
		Name: "x", Kind: KindStatic, Listen: 80,
		Domains: []string{"a.com\nserver_name evil;"},
		Root:    "/www/wwwroot/x", Index: "index.html",
		AccessLog: "/l/a.log", ErrorLog: "/l/e.log",
	}
	if _, err := renderVHost(v); err == nil {
		t.Error("renderVHost must reject control characters in fields")
	}
}

func TestListenPortHonored(t *testing.T) {
	v, err := buildVHost(createRequest{
		Domains: []string{"a.com"}, Kind: "static", Listen: 8080,
	}, testSettings())
	if err != nil {
		t.Fatalf("buildVHost: %v", err)
	}
	out, _ := renderVHost(v)
	if !strings.Contains(out, "listen 8080;") {
		t.Errorf("custom listen port not honored\n%s", out)
	}
}
