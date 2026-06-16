package loadbalancer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/go-chi/chi/v5"
)

// mockNginx 记录调用顺序与配置内容,可模拟 nginx -t 失败。
type mockNginx struct {
	configs   map[string]string
	testErr   error // 非 nil 时 Test() 失败
	reloadErr error
	reloads   int
	tests     int
	writes    int
	removes   int
}

func newMockNginx() *mockNginx { return &mockNginx{configs: map[string]string{}} }

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

func validCreate() createRequest {
	return createRequest{
		Name:       "web",
		Algo:       "round-robin",
		ServerName: "lb.example.com",
		Backends: []backendRequest{
			{Host: "10.0.0.1", Port: 8080, Weight: 3},
			{Host: "10.0.0.2", Port: 8080},
		},
	}
}

func TestMetaSwitchableNetworkCategory(t *testing.T) {
	m, _ := newTestModule(t, "admin", newMockNginx())
	meta := m.Meta()
	if meta.ID != "loadbalancer" || meta.AlwaysOn || meta.Category != "网站" || meta.Name != "负载均衡" {
		t.Errorf("unexpected meta: %+v", meta)
	}
}

func TestNav(t *testing.T) {
	m, _ := newTestModule(t, "admin", newMockNginx())
	nav := m.Nav()
	if len(nav) != 1 || nav[0].Icon != "git-fork" || nav[0].Path != "/loadbalancer" {
		t.Errorf("unexpected nav: %+v", nav)
	}
}

func TestCreateAppliesAndAudits(t *testing.T) {
	ng := newMockNginx()
	m, audited := newTestModule(t, "operator", ng)
	rec := do(m, "POST", "/groups", validCreate(), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s)", rec.Code, rec.Body.String())
	}
	if ng.writes == 0 || ng.tests == 0 || ng.reloads == 0 {
		t.Errorf("create must write+test+reload, got w=%d t=%d r=%d", ng.writes, ng.tests, ng.reloads)
	}
	if *audited != 1 {
		t.Errorf("create must audit once, got %d", *audited)
	}
	cfg, ok := ng.configs["web"]
	if !ok {
		t.Fatal("config for web not written")
	}
	// 模板生成检查:upstream 块 + server proxy_pass + weight。
	for _, want := range []string{
		"upstream xpanel_lb_web {",
		"server 10.0.0.1:8080 weight=3;",
		"server 10.0.0.2:8080 weight=1;",
		"proxy_pass http://xpanel_lb_web;",
		"server_name lb.example.com;",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
}

func TestCreateAlgorithmsRendered(t *testing.T) {
	cases := map[string]string{
		"least_conn": "least_conn;",
		"ip_hash":    "ip_hash;",
	}
	for algo, want := range cases {
		ng := newMockNginx()
		m, _ := newTestModule(t, "operator", ng)
		req := validCreate()
		req.Algo = algo
		rec := do(m, "POST", "/groups", req, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s = %d (%s)", algo, rec.Code, rec.Body.String())
		}
		if !strings.Contains(ng.configs["web"], want) {
			t.Errorf("algo %s: config missing %q:\n%s", algo, want, ng.configs["web"])
		}
	}
}

// round-robin 是 nginx 默认,不应写出任何算法指令。
func TestRoundRobinNoDirective(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	rec := do(m, "POST", "/groups", validCreate(), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}
	cfg := ng.configs["web"]
	if strings.Contains(cfg, "least_conn") || strings.Contains(cfg, "ip_hash") {
		t.Errorf("round-robin should emit no algo directive:\n%s", cfg)
	}
}

func TestCreateHealthCheckParams(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	req := validCreate()
	req.Backends = []backendRequest{{Host: "10.0.0.1", Port: 80, MaxFails: 3, FailTimeout: "30s"}}
	rec := do(m, "POST", "/groups", req, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s)", rec.Code, rec.Body.String())
	}
	if want := "server 10.0.0.1:80 weight=1 max_fails=3 fail_timeout=30s;"; !strings.Contains(ng.configs["web"], want) {
		t.Errorf("config missing %q:\n%s", want, ng.configs["web"])
	}
}

// nginx -t 失败时绝不 reload,且组不入库,坏配置被移除。
func TestCreateNginxTestFailNoReload(t *testing.T) {
	ng := newMockNginx()
	ng.testErr = errNginxTest
	m, audited := newTestModule(t, "operator", ng)
	rec := do(m, "POST", "/groups", validCreate(), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("nginx -t fail should 400, got %d", rec.Code)
	}
	if ng.reloads != 0 {
		t.Errorf("must NOT reload when nginx -t fails, got reloads=%d", ng.reloads)
	}
	if _, ok := ng.configs["web"]; ok {
		t.Error("bad config must be removed after failed test")
	}
	if *audited != 0 {
		t.Error("failed create must not audit success")
	}
	groups, _ := m.ls.list()
	if len(groups) != 0 {
		t.Errorf("group must not be persisted on nginx -t failure, got %d", len(groups))
	}
}

// 恶意后端 host 含换行,必须在校验层被拒,绝不触达 nginx。
func TestCreateRejectsMaliciousBackendNoExec(t *testing.T) {
	ng := newMockNginx()
	m, audited := newTestModule(t, "operator", ng)
	req := validCreate()
	req.Backends = []backendRequest{{Host: "10.0.0.1\n    server evil.com;", Port: 80}}
	rec := do(m, "POST", "/groups", req, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malicious backend should 400, got %d", rec.Code)
	}
	if ng.writes != 0 || ng.tests != 0 || ng.reloads != 0 {
		t.Errorf("malicious input must never reach nginx, got w=%d t=%d r=%d", ng.writes, ng.tests, ng.reloads)
	}
	if *audited != 0 {
		t.Error("rejected input must not audit")
	}
}

// 恶意 upstream 名含注入字符,必须被拒。
func TestCreateRejectsMaliciousNameNoExec(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	for _, name := range []string{"web;\n}", "web upstream", "../../etc", "web}{"} {
		req := validCreate()
		req.Name = name
		rec := do(m, "POST", "/groups", req, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("malicious name %q should 400, got %d", name, rec.Code)
		}
	}
	if ng.writes != 0 {
		t.Error("malicious name must never reach nginx")
	}
}

func TestCreateRejectsBadAlgoAndPort(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)

	bad := validCreate()
	bad.Algo = "random; drop"
	if rec := do(m, "POST", "/groups", bad, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad algo should 400, got %d", rec.Code)
	}

	bad = validCreate()
	bad.Backends = []backendRequest{{Host: "10.0.0.1", Port: 99999}}
	if rec := do(m, "POST", "/groups", bad, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad port should 400, got %d", rec.Code)
	}

	bad = validCreate()
	bad.Backends = nil
	if rec := do(m, "POST", "/groups", bad, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("empty backends should 400, got %d", rec.Code)
	}

	bad = validCreate()
	bad.Backends = []backendRequest{{Host: "10.0.0.1", Port: 80, Weight: 999}}
	if rec := do(m, "POST", "/groups", bad, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad weight should 400, got %d", rec.Code)
	}

	bad = validCreate()
	bad.Backends = []backendRequest{{Host: "10.0.0.1", Port: 80, FailTimeout: "30; reload"}}
	if rec := do(m, "POST", "/groups", bad, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad fail_timeout should 400, got %d", rec.Code)
	}
}

func TestCreateRequiresWriter(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "readonly", ng)
	rec := do(m, "POST", "/groups", validCreate(), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create should 403, got %d", rec.Code)
	}
	if ng.writes != 0 {
		t.Error("forbidden create must not touch nginx")
	}
}

func TestCreateDuplicateNameConflict(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	seedGroup(t, m)
	rec := do(m, "POST", "/groups", validCreate(), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate name should 409, got %d", rec.Code)
	}
}

func TestDeleteRequiresConfirmAndAdmin(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedGroup(t, m)

	rec := do(m, "DELETE", "/groups/"+itoa(id), nil, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "DELETE", "/groups/"+itoa(id), nil, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator delete should 403, got %d", rec.Code)
	}
}

func TestDeleteAdminConfirmedSucceeds(t *testing.T) {
	ng := newMockNginx()
	m, audited := newTestModule(t, "admin", ng)
	id := seedGroup(t, m)
	*audited = 0
	rec := do(m, "DELETE", "/groups/"+itoa(id), nil, map[string]string{"X-Confirm-Danger": "yes"})
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
	id := seedGroup(t, m)
	rec := do(m, "POST", "/groups/"+itoa(id)+"/disable", nil, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("disable without confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "POST", "/groups/"+itoa(id)+"/disable", nil, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator disable should 403, got %d", rec.Code)
	}
}

func TestEnableOperatorAllowed(t *testing.T) {
	ng := newMockNginx()
	m, _ := newTestModule(t, "operator", ng)
	id := seedGroup(t, m)
	rec := do(m, "POST", "/groups/"+itoa(id)+"/enable", nil, nil)
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
	if set.ConfDir != "/etc/nginx/conf.d" {
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

	rec := do(m, "PUT", "/settings", Settings{ConfDir: "/etc/nginx/sites"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin put valid settings should 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	// 非法设置(相对路径)被拒。
	rec = do(m, "PUT", "/settings", Settings{ConfDir: "relative"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid settings should 400, got %d", rec.Code)
	}
	// 注入字符目录被拒。
	rec = do(m, "PUT", "/settings", Settings{ConfDir: "/etc/nginx; rm -rf /"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("settings with shell metachar should 400, got %d", rec.Code)
	}

	got, _ := m.ls.getSettings()
	if got.ConfDir != "/etc/nginx/sites" {
		t.Errorf("settings not persisted, got %+v", got)
	}
}

// --- helpers ---

var errNginxTest = &testError{"nginx -t failed"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

func seedGroup(t *testing.T, m *Module) int64 {
	t.Helper()
	rec := do(m, "POST", "/groups", validCreate(), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed group failed: %d (%s)", rec.Code, rec.Body.String())
	}
	var g LBGroup
	json.Unmarshal(rec.Body.Bytes(), &g)
	return g.ID
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }
