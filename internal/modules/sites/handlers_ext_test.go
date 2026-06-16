package sites

import (
	"encoding/json"
	"net/http"
	"testing"
)

// seedPHP 建一个 PHP 站点并返回 id。
func seedPHP(t *testing.T, m *Module) int64 {
	t.Helper()
	rec := do(m, "POST", "/sites", createRequest{Domains: []string{"blog.example.com"}, Kind: "php", PHPVersion: "8.2"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed php failed: %d (%s)", rec.Code, rec.Body.String())
	}
	var s Site
	json.Unmarshal(rec.Body.Bytes(), &s)
	return s.ID
}

func seedProxy(t *testing.T, m *Module) int64 {
	t.Helper()
	rec := do(m, "POST", "/sites", createRequest{Domains: []string{"api.example.com"}, Kind: "proxy", Upstream: "http://127.0.0.1:3000"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed proxy failed: %d (%s)", rec.Code, rec.Body.String())
	}
	var s Site
	json.Unmarshal(rec.Body.Bytes(), &s)
	return s.ID
}

func getSite(t *testing.T, m *Module, id int64) Site {
	t.Helper()
	s, err := m.ss.get(id)
	if err != nil {
		t.Fatalf("get site: %v", err)
	}
	return s
}

func TestRewriteTemplatesReturned(t *testing.T) {
	m, _ := newTestModule(t, "readonly", newMockNginx())
	rec := do(m, "GET", "/rewrite-templates", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rewrite-templates = %d", rec.Code)
	}
	var tpls []RewriteTemplate
	json.Unmarshal(rec.Body.Bytes(), &tpls)
	want := map[string]bool{"wordpress": false, "laravel": false, "thinkphp": false, "discuz": false, "empirecms": false, "typecho": false}
	for _, tp := range tpls {
		if _, ok := want[tp.ID]; ok {
			want[tp.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("rewrite template %q missing", id)
		}
	}
}

func TestPutRewriteAppliesAndRegens(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedPHP(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/rewrite", map[string]string{"template": "wordpress"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put rewrite = %d (%s)", rec.Code, rec.Body.String())
	}
	cfg := ng.configs["blog.example.com"]
	if !contains(cfg, "try_files $uri $uri/ /index.php?$args;") {
		t.Errorf("rewrite not applied to config\n%s", cfg)
	}
	if getSite(t, m, id).RewriteRules == "" {
		t.Error("rewrite rules not persisted")
	}
}

func TestPutRewriteRejectsInjection(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedPHP(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/rewrite", map[string]string{"rewrite_rules": "rewrite x\x00 evil"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection rewrite should 400, got %d", rec.Code)
	}
}

func TestPutPHPVersion(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedPHP(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/php", map[string]string{"php_version": "8.3"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put php = %d (%s)", rec.Code, rec.Body.String())
	}
	if !contains(ng.configs["blog.example.com"], "php8.3-fpm.sock") {
		t.Errorf("php version change not reflected in config\n%s", ng.configs["blog.example.com"])
	}
	// 非法版本
	rec = do(m, "PUT", "/sites/"+itoa(id)+"/php", map[string]string{"php_version": "8.3;rm"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid php version should 400, got %d", rec.Code)
	}
}

func TestPutProxy(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedProxy(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/proxy", map[string]string{"proxy_target": "http://10.0.0.5:8080"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put proxy = %d (%s)", rec.Code, rec.Body.String())
	}
	if !contains(ng.configs["api.example.com"], "proxy_pass http://10.0.0.5:8080;") {
		t.Errorf("proxy target not applied\n%s", ng.configs["api.example.com"])
	}
	// 注入
	rec = do(m, "PUT", "/sites/"+itoa(id)+"/proxy", map[string]string{"proxy_target": "http://x:80\nproxy_pass evil;"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection proxy should 400, got %d", rec.Code)
	}
}

func TestPutDomains(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/domains",
		map[string]any{"bindings": []Domain{{"example.com", 80}, {"www.example.com", 80}}}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put domains = %d (%s)", rec.Code, rec.Body.String())
	}
	if !contains(ng.configs["example.com"], "server_name example.com www.example.com;") {
		t.Errorf("domains not applied\n%s", ng.configs["example.com"])
	}
	// 注入域名
	rec = do(m, "PUT", "/sites/"+itoa(id)+"/domains",
		map[string]any{"domains": []string{"a.com\nserver_name evil;"}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection domain should 400, got %d", rec.Code)
	}
}

func TestDirProtectAddListDelete(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	rec := do(m, "POST", "/sites/"+itoa(id)+"/dir-protect",
		map[string]string{"path": "/admin", "username": "admin", "password": "secret123"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("add dir-protect = %d (%s)", rec.Code, rec.Body.String())
	}
	// .htpasswd 写了,且口令是哈希不是明文
	hp := ng.htpasswds["example.com"]
	if !contains(hp, "admin:$apr1$") {
		t.Errorf("htpasswd not written as apr1 hash: %q", hp)
	}
	if contains(hp, "secret123") {
		t.Error("plaintext password leaked into htpasswd")
	}
	// 配置含 auth_basic
	if !contains(ng.configs["example.com"], "auth_basic_user_file") {
		t.Errorf("config missing auth_basic\n%s", ng.configs["example.com"])
	}
	// 持久化的哈希非明文
	st := getSite(t, m, id)
	if len(st.DirProtect) != 1 || contains(st.DirProtect[0].PassHash, "secret123") {
		t.Errorf("dirprotect persisted wrong: %+v", st.DirProtect)
	}
	// list 不回显哈希
	rec = do(m, "GET", "/sites/"+itoa(id)+"/dir-protect", nil, nil)
	if contains(rec.Body.String(), "apr1") || contains(rec.Body.String(), "passhash") {
		t.Errorf("dir-protect list leaked hash: %s", rec.Body.String())
	}
	// 非法路径
	rec = do(m, "POST", "/sites/"+itoa(id)+"/dir-protect",
		map[string]string{"path": "/a;deny", "username": "x", "password": "y"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad path should 400, got %d", rec.Code)
	}
	// delete
	rec = do(m, "DELETE", "/sites/"+itoa(id)+"/dir-protect", map[string]string{"path": "/admin"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete dir-protect = %d", rec.Code)
	}
	if len(getSite(t, m, id).DirProtect) != 0 {
		t.Error("dir-protect not removed")
	}
}

func TestPutRedirects(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/redirects",
		map[string]any{"redirects": []Redirect{{From: "/old", To: "https://example.com/new", Code: 301}}}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put redirects = %d (%s)", rec.Code, rec.Body.String())
	}
	if !contains(ng.configs["example.com"], "return 301 https://example.com/new;") {
		t.Errorf("redirect not applied\n%s", ng.configs["example.com"])
	}
	// 注入目标
	rec = do(m, "PUT", "/sites/"+itoa(id)+"/redirects",
		map[string]any{"redirects": []Redirect{{From: "/x", To: "javascript:alert(1)", Code: 301}}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection redirect should 400, got %d", rec.Code)
	}
	// 非法 code
	rec = do(m, "PUT", "/sites/"+itoa(id)+"/redirects",
		map[string]any{"redirects": []Redirect{{From: "/x", To: "/y", Code: 307}}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad code should 400, got %d", rec.Code)
	}
}

func TestPutAntiLeech(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/anti-leech",
		AntiLeech{Enabled: true, Extensions: []string{"jpg", "png"}, AllowedReferers: []string{"example.com"}}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put anti-leech = %d (%s)", rec.Code, rec.Body.String())
	}
	cfg := ng.configs["example.com"]
	if !contains(cfg, "valid_referers none blocked example.com;") || !contains(cfg, "return 403;") {
		t.Errorf("anti-leech not applied\n%s", cfg)
	}
	// 注入扩展名
	rec = do(m, "PUT", "/sites/"+itoa(id)+"/anti-leech",
		AntiLeech{Enabled: true, Extensions: []string{"jpg) { deny all; }"}, AllowedReferers: []string{"a.com"}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection extension should 400, got %d", rec.Code)
	}
}

func TestPutDefaultDocs(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/default-docs",
		map[string]any{"index_docs": []string{"index.php", "default.html"}}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put default-docs = %d (%s)", rec.Code, rec.Body.String())
	}
	if !contains(ng.configs["example.com"], "index index.php default.html;") {
		t.Errorf("default docs not applied\n%s", ng.configs["example.com"])
	}
	// 注入
	rec = do(m, "PUT", "/sites/"+itoa(id)+"/default-docs",
		map[string]any{"index_docs": []string{"index.php;deny"}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection doc should 400, got %d", rec.Code)
	}
}

func TestPutSSLUploadDualBlock(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/ssl", map[string]any{
		"ssl_enabled": true, "force_https": true, "hsts": true,
		"cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		"key_pem":  "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put ssl = %d (%s)", rec.Code, rec.Body.String())
	}
	cfg := ng.configs["example.com"]
	if !contains(cfg, "listen 443 ssl;") || !contains(cfg, "return 301 https://") || !contains(cfg, "Strict-Transport-Security") {
		t.Errorf("ssl dual block not generated\n%s", cfg)
	}
}

func TestLogsTail(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	st := getSite(t, m, id)
	ng.logs[st.AccessLog] = "line1\nline2\nline3\n"
	rec := do(m, "GET", "/sites/"+itoa(id)+"/logs?type=access&tail=2", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("logs = %d", rec.Code)
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["content"] != "line2\nline3" {
		t.Errorf("tail content = %q", out["content"])
	}
}

func TestRunDirSet(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/run-dir", map[string]string{"subdir": "public"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put run-dir = %d (%s)", rec.Code, rec.Body.String())
	}
	if !contains(ng.configs["example.com"], "root /www/wwwroot/example.com/public;") {
		t.Errorf("run dir not applied\n%s", ng.configs["example.com"])
	}
	// 穿越拒绝
	rec = do(m, "PUT", "/sites/"+itoa(id)+"/run-dir", map[string]string{"subdir": "../../etc"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal run-dir should 400, got %d", rec.Code)
	}
}

func TestExtSettingsRequireWriter(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "readonly", ng)
	id := seedSiteAs(t, "operator")
	_ = id
	// readonly 角色对各写端点应 403
	for _, ep := range []struct {
		method, path string
		body         any
	}{
		{"PUT", "/sites/1/rewrite", map[string]string{"rewrite_rules": ""}},
		{"PUT", "/sites/1/proxy", map[string]string{"proxy_target": "http://x:80"}},
		{"POST", "/sites/1/dir-protect", map[string]string{"path": "/a", "username": "u", "password": "p"}},
		{"PUT", "/sites/1/redirects", map[string]any{"redirects": []Redirect{}}},
		{"PUT", "/sites/1/anti-leech", AntiLeech{}},
	} {
		rec := do(m, ep.method, ep.path, ep.body, nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s by readonly = %d, want 403", ep.method, ep.path, rec.Code)
		}
	}
}

// seedSiteAs 在独立模块上以指定角色建站(仅用于权限测试需要一个已存在 id 的场景)。
func seedSiteAs(t *testing.T, role string) int64 {
	t.Helper()
	m, _ := newTestModule(t, role, newMockNginx())
	return seedSite(t, m)
}

// nginx -t 失败时设置变更不落库,且回滚旧配置。
func TestExtChangeNginxFailRollsBack(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	orig := ng.configs["example.com"]
	ng.testErr = errNginxTest
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/default-docs",
		map[string]any{"index_docs": []string{"index.php"}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("nginx -t fail should 400, got %d", rec.Code)
	}
	if ng.configs["example.com"] != orig {
		t.Error("rejected change must restore original config")
	}
	if len(getSite(t, m, id).IndexDocs) != 2 {
		t.Error("rejected change must not persist new docs")
	}
}
