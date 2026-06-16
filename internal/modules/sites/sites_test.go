package sites

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/go-chi/chi/v5"
)

// testSettings 是单测用的默认建站设置。
func testSettings() Settings {
	return Settings{
		WebRoot:   "/www/wwwroot",
		ConfDir:   "/etc/nginx/conf.d",
		LogDir:    "/www/wwwlogs",
		PHPSocket: "/run/php/php-fpm.sock",
	}
}

// mockNginx 记录调用顺序与配置内容,可模拟 nginx -t 失败。
type mockNginx struct {
	configs   map[string]string
	htpasswds map[string]string
	logs      map[string]string // path -> content
	testErr   error             // 非 nil 时 Test() 失败
	reloadErr error
	reloads   int
	tests     int
	writes    int
	removes   int
}

func newMockNginx() *mockNginx {
	return &mockNginx{configs: map[string]string{}, htpasswds: map[string]string{}, logs: map[string]string{}}
}

func (n *mockNginx) WriteConfig(name, content string) error {
	n.writes++
	n.configs[name] = content
	return nil
}
func (n *mockNginx) RemoveConfig(name string) error {
	n.removes++
	delete(n.configs, name)
	return nil
}
func (n *mockNginx) Test() error {
	n.tests++
	return n.testErr
}
func (n *mockNginx) Reload() error {
	n.reloads++
	return n.reloadErr
}
func (n *mockNginx) Available() error { return nil }
func (n *mockNginx) WriteHtpasswd(name, content string) error {
	n.htpasswds[name] = content
	return nil
}
func (n *mockNginx) RemoveHtpasswd(name string) error {
	delete(n.htpasswds, name)
	return nil
}
func (n *mockNginx) ReadLog(path string, tail int) (string, error) {
	return lastLines(n.logs[path], tail), nil
}
func (n *mockNginx) OpenLog(path string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(n.logs[path])), nil
}
func (n *mockNginx) WriteCert(name, cert, key string) (string, string, error) {
	cp := "/etc/nginx/conf.d/ssl/" + name + "/fullchain.pem"
	kp := "/etc/nginx/conf.d/ssl/" + name + "/privkey.pem"
	n.configs["cert:"+name] = cert
	return cp, kp, nil
}

func newTestModule(t *testing.T, role string, ng *mockNginx) (*Module, *int) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	audited := new(int)
	m := New(st, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	})
	m.newNginx = func(string) Nginx { return ng }
	m.available = func() error { return nil }
	return m, audited
}

func do(m *Module, method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	m.Routes(r)
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestMetaSwitchableNetworkCategory(t *testing.T) {
	m, _ := newTestModule(t, "admin", newMockNginx())
	meta := m.Meta()
	if meta.ID != "sites" || meta.AlwaysOn || meta.Category != "网站" {
		t.Errorf("unexpected meta: %+v", meta)
	}
}

func TestCreateStaticAppliesAndAudits(t *testing.T) {
	ng := newMockNginx()
	m, audited := newTestModule(t, "operator", ng)
	rec := do(m, "POST", "/sites", createRequest{Domains: []string{"example.com"}, Kind: "static"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create static = %d (%s)", rec.Code, rec.Body.String())
	}
	if ng.writes == 0 || ng.tests == 0 || ng.reloads == 0 {
		t.Errorf("create must write+test+reload, got w=%d t=%d r=%d", ng.writes, ng.tests, ng.reloads)
	}
	if *audited != 1 {
		t.Errorf("create must audit once, got %d", *audited)
	}
	if _, ok := ng.configs["example.com"]; !ok {
		t.Error("config for example.com not written")
	}
}

// nginx -t 失败时绝不 reload,且站点不入库。
func TestCreateNginxTestFailNoReload(t *testing.T) {
	ng := newMockNginx()
	ng.testErr = errNginxTest
	m, audited := newTestModule(t, "operator", ng)
	rec := do(m, "POST", "/sites", createRequest{Domains: []string{"example.com"}, Kind: "static"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("nginx -t fail should 400, got %d", rec.Code)
	}
	if ng.reloads != 0 {
		t.Errorf("must NOT reload when nginx -t fails, got reloads=%d", ng.reloads)
	}
	if _, ok := ng.configs["example.com"]; ok {
		t.Error("bad config must be removed after failed test")
	}
	if *audited != 0 {
		t.Error("failed create must not audit success")
	}
	sites, _ := m.ss.list()
	if len(sites) != 0 {
		t.Errorf("site must not be persisted on nginx -t failure, got %d", len(sites))
	}
}

func TestCreateRejectsMaliciousDomainNoExec(t *testing.T) {
	ng := newMockNginx()
	m, audited := newTestModule(t, "operator", ng)
	rec := do(m, "POST", "/sites",
		createRequest{Domains: []string{"a.com\nserver_name evil;"}, Kind: "static"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malicious domain should 400, got %d", rec.Code)
	}
	if ng.writes != 0 || ng.tests != 0 || ng.reloads != 0 {
		t.Errorf("malicious input must never reach nginx, got w=%d t=%d r=%d", ng.writes, ng.tests, ng.reloads)
	}
	if *audited != 0 {
		t.Error("rejected input must not audit")
	}
}

func TestCreateRequiresWriter(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "readonly", ng)
	rec := do(m, "POST", "/sites", createRequest{Domains: []string{"a.com"}, Kind: "static"}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create should 403, got %d", rec.Code)
	}
	if ng.writes != 0 {
		t.Error("forbidden create must not touch nginx")
	}
}

func TestDeleteRequiresConfirmAndAdmin(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)

	// 无确认头 → 428
	rec := do(m, "DELETE", "/sites/"+itoa(id), nil, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	// 有确认头但 operator 角色 → 403
	rec = do(m, "DELETE", "/sites/"+itoa(id), nil, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator delete should 403, got %d", rec.Code)
	}
}

func TestDeleteAdminConfirmedSucceeds(t *testing.T) {
	ng := newMockNginx()
	m, audited := newTestModule(t, "admin", ng)
	id := seedSite(t, m)
	*audited = 0
	rec := do(m, "DELETE", "/sites/"+itoa(id), nil, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin confirmed delete should 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	if ng.removes == 0 {
		t.Error("delete must remove nginx config")
	}
	if *audited != 1 {
		t.Errorf("delete must audit once, got %d", *audited)
	}
}

func TestDisableRequiresConfirmAndAdmin(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	// operator disable without confirm → 428
	rec := do(m, "POST", "/sites/"+itoa(id)+"/disable", nil, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("disable without confirm should 428, got %d", rec.Code)
	}
	// confirm but operator → 403
	rec = do(m, "POST", "/sites/"+itoa(id)+"/disable", nil, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator disable should 403, got %d", rec.Code)
	}
}

func TestEnableOperatorAllowed(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	rec := do(m, "POST", "/sites/"+itoa(id)+"/enable", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator enable should 200, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestSettingsGetDefaults(t *testing.T) {
	m, _ := newTestModule(t, "readonly", newMockNginx())
	rec := do(m, "GET", "/settings", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get settings = %d", rec.Code)
	}
	var set Settings
	json.Unmarshal(rec.Body.Bytes(), &set)
	if set.WebRoot != "/www/wwwroot" || set.ConfDir != "/etc/nginx/conf.d" {
		t.Errorf("unexpected default settings: %+v", set)
	}
}

func TestSettingsPutRequiresAdmin(t *testing.T) {
	m, _ := newTestModule(t, "operator", newMockNginx())
	rec := do(m, "PUT", "/settings", DefaultSettings(), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator put settings should 403, got %d", rec.Code)
	}
}

func TestSettingsPutValidatedAndUsed(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "admin", ng)
	// 改 web 根
	newSet := Settings{WebRoot: "/srv/web", ConfDir: "/etc/nginx/sites", LogDir: "/var/log/nginx", PHPSocket: "/run/php/x.sock"}
	rec := do(m, "PUT", "/settings", newSet, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin put valid settings should 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	// 非法设置(相对路径)被拒
	rec = do(m, "PUT", "/settings", Settings{WebRoot: "relative", ConfDir: "/a", LogDir: "/b", PHPSocket: "/c.sock"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid settings should 400, got %d", rec.Code)
	}
	// 建站应使用新 web 根
	rec = do(m, "POST", "/sites", createRequest{Domains: []string{"example.com"}, Kind: "static"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create after settings change = %d (%s)", rec.Code, rec.Body.String())
	}
	if cfg := ng.configs["example.com"]; !contains(cfg, "/srv/web/example.com") {
		t.Errorf("create should use new web root, config:\n%s", cfg)
	}
}

func TestEditConfigRejectedKeepsOld(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "admin", ng)
	id := seedSite(t, m)
	orig := ng.configs["example.com"]
	ng.testErr = errNginxTest // 新配置 nginx -t 失败
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/config",
		map[string]string{"config": "server { bad }"}, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rejected edit should 400, got %d", rec.Code)
	}
	if ng.configs["example.com"] != orig {
		t.Error("rejected edit must restore original config")
	}
}

// 写原始 nginx 配置可绕过建站白名单(如 location root /; 读 /etc/passwd),
// 属危险操作:operator 即便提交确认头也必须 403。
func TestEditConfigRequiresConfirmAndAdmin(t *testing.T) {
	ng := newMockNginx()
	m, audited := newTestModule(t, "operator", ng)
	id := seedSite(t, m)
	orig := ng.configs["example.com"]
	*audited = 0
	raw := map[string]string{"config": "server { listen 80; location / { root /; } }"}

	// operator 无确认头 → 428
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/config", raw, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("edit without confirm should 428, got %d", rec.Code)
	}
	// operator 带确认头但非 admin → 403
	rec = do(m, "PUT", "/sites/"+itoa(id)+"/config", raw, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator edit should 403, got %d", rec.Code)
	}
	if ng.configs["example.com"] != orig {
		t.Error("forbidden edit must not change config")
	}
	if *audited != 0 {
		t.Error("forbidden edit must not audit")
	}
}

func TestEditConfigAdminConfirmedSucceeds(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "admin", ng)
	id := seedSite(t, m)
	rec := do(m, "PUT", "/sites/"+itoa(id)+"/config",
		map[string]string{"config": "server { listen 80; }"}, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin confirmed edit should 200, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// --- helpers ---

var errNginxTest = &testError{"nginx -t failed"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

func seedSite(t *testing.T, m *Module) int64 {
	t.Helper()
	rec := do(m, "POST", "/sites", createRequest{Domains: []string{"example.com"}, Kind: "static"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed site failed: %d (%s)", rec.Code, rec.Body.String())
	}
	var s Site
	json.Unmarshal(rec.Body.Bytes(), &s)
	return s.ID
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }
