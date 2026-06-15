package nodejs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockPM 记录调用并返回可控结果,隔离真实 supervisorctl/文件系统。
type mockPM struct {
	applies  []string // 写过配置的 name
	removes  []string
	actions  []string // "verb name"
	lastSpec ProcessSpec
	avail    error
	applyErr error
	versions []string
}

func (m *mockPM) Apply(_ string, spec ProcessSpec) error {
	m.applies = append(m.applies, spec.Name)
	m.lastSpec = spec
	return m.applyErr
}
func (m *mockPM) Remove(_, name string) error { m.removes = append(m.removes, name); return nil }
func (m *mockPM) Action(verb, name string) (string, error) {
	m.actions = append(m.actions, verb+" "+name)
	return "ok", nil
}
func (m *mockPM) Status(name string) (string, error)               { return "RUNNING " + name, nil }
func (m *mockPM) TailLog(name string, _ int, _ bool) (string, error) { return "log " + name, nil }
func (m *mockPM) NodeVersions() []string                           { return m.versions }
func (m *mockPM) Available() error                                 { return m.avail }

func newTestModule(t *testing.T, role string, pm ProcessManager) (*Module, *int) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	audited := new(int)
	m := New(st, pm, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	})
	return m, audited
}

func do(m *Module, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	m.Routes(r)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestMetaSwitchable(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{})
	meta := m.Meta()
	if meta.ID != "nodejs" || meta.AlwaysOn {
		t.Errorf("must be id=nodejs, not AlwaysOn, got %+v", meta)
	}
	if meta.Category != "网站" || meta.Name != "Node 项目" {
		t.Errorf("unexpected meta %+v", meta)
	}
}

func TestNavPath(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{})
	nav := m.Nav()
	if len(nav) != 1 || nav[0].Path != "/nodejs" {
		t.Errorf("unexpected nav %+v", nav)
	}
}

func TestHealthCheckUnavailable(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{avail: http.ErrNotSupported})
	if m.HealthCheck() == nil {
		t.Error("HealthCheck should fail when backend unavailable")
	}
}

func TestCreateHappyPath(t *testing.T) {
	pm := &mockPM{}
	m, audited := newTestModule(t, "operator", pm)
	body := `{"name":"web","directory":"web","command":"node app.js","port":3000,"node_version":"18.19.0"}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(pm.applies) != 1 || pm.applies[0] != "web" {
		t.Fatalf("expected apply for web, got %v", pm.applies)
	}
	if pm.lastSpec.Directory != "/www/nodejs/web" {
		t.Fatalf("directory should resolve under base, got %q", pm.lastSpec.Directory)
	}
	if pm.lastSpec.Port != 3000 || pm.lastSpec.NodePath != "/usr/local/bin" {
		t.Fatalf("spec wrong: %+v", pm.lastSpec)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestCreateRejectsInjectionName(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web;rm -rf /","directory":"web","command":"node app.js","port":3000}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection name should 400, got %d", rec.Code)
	}
	if len(pm.applies) != 0 {
		t.Fatalf("must not apply on invalid input, got %v", pm.applies)
	}
}

func TestCreateRejectsInjectionCommand(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := "{\"name\":\"web\",\"directory\":\"web\",\"command\":\"node app.js\\nmalicious=1\",\"port\":3000}"
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("newline command should 400, got %d", rec.Code)
	}
}

func TestCreateRejectsPathTraversal(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web","directory":"../../etc","command":"node app.js","port":3000}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("path traversal dir should 400, got %d", rec.Code)
	}
	if len(pm.applies) != 0 {
		t.Fatal("must not apply on path escape")
	}
}

func TestCreateRejectsBadPort(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web","directory":"web","command":"node app.js","port":0}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("port 0 should 400, got %d", rec.Code)
	}
}

func TestCreateRejectsBadNodeVersion(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web","directory":"web","command":"node app.js","port":3000,"node_version":"latest; rm"}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad node version should 400, got %d", rec.Code)
	}
}

func TestCreateRequiresWriter(t *testing.T) {
	pm := &mockPM{}
	m, audited := newTestModule(t, "readonly", pm)
	body := `{"name":"web","directory":"web","command":"node app.js","port":3000}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create should 403, got %d", rec.Code)
	}
	if *audited != 0 || len(pm.applies) != 0 {
		t.Fatal("forbidden create must not audit or apply")
	}
}

func TestStopRequiresConfirm(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	id := seedProject(t, m)
	rec := do(m, "POST", "/projects/"+id+"/stop", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("stop without confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "POST", "/projects/"+id+"/stop", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("stop with confirm should 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRestartNoConfirmNeeded(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	id := seedProject(t, m)
	rec := do(m, "POST", "/projects/"+id+"/restart", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("restart should 200, got %d", rec.Code)
	}
}

func TestDeleteRequiresAdminAndConfirm(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	id := seedProject(t, m)

	rec := do(m, "DELETE", "/projects/"+id, "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "DELETE", "/projects/"+id, "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator delete should 403, got %d", rec.Code)
	}
}

func TestDeleteAdminConfirmedRemovesConfig(t *testing.T) {
	pm := &mockPM{}
	m, audited := newTestModule(t, "admin", pm)
	id := seedProject(t, m)
	*audited = 0
	rec := do(m, "DELETE", "/projects/"+id, "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin confirmed delete should 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(pm.removes) != 1 {
		t.Fatalf("expected config removal, got %v", pm.removes)
	}
	// 删除前应先 stop。
	if len(pm.actions) != 1 || !strings.HasPrefix(pm.actions[0], "stop ") {
		t.Fatalf("expected stop before delete, got %v", pm.actions)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestPutSettingsRequiresAdmin(t *testing.T) {
	m, _ := newTestModule(t, "operator", &mockPM{})
	rec := do(m, "PUT", "/settings", `{"base_dir":"/a","node_dir":"/b","conf_dir":"/c","log_dir":"/d"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator put settings should 403, got %d", rec.Code)
	}
}

func TestPutSettingsValidatesPaths(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{})
	rec := do(m, "PUT", "/settings", `{"base_dir":"relative","node_dir":"/b","conf_dir":"/c","log_dir":"/d"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-absolute base_dir should 400, got %d", rec.Code)
	}
}

func TestSettingsRoundTripViaAPI(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{})
	rec := do(m, "PUT", "/settings",
		`{"base_dir":"/srv/node","node_dir":"/opt/node/bin","conf_dir":"/etc/sv","log_dir":"/var/log/node"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin put settings should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = do(m, "GET", "/settings", "", nil)
	if !strings.Contains(rec.Body.String(), "/srv/node") {
		t.Fatalf("settings not persisted: %s", rec.Body.String())
	}
}

func TestSettingsAffectProjectDir(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "admin", pm)
	rec := do(m, "PUT", "/settings",
		`{"base_dir":"/srv/node","node_dir":"/opt/node/bin","conf_dir":"/etc/sv","log_dir":"/var/log/node"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put settings failed: %d", rec.Code)
	}
	body := `{"name":"web","directory":"web","command":"node app.js","port":3000}`
	rec = do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create failed: %d %s", rec.Code, rec.Body.String())
	}
	if pm.lastSpec.Directory != "/srv/node/web" || pm.lastSpec.NodePath != "/opt/node/bin" {
		t.Fatalf("settings not applied to spec: %+v", pm.lastSpec)
	}
}

func TestVersionsEndpoint(t *testing.T) {
	pm := &mockPM{versions: []string{"v18.19.0", "v20.1.0"}}
	m, _ := newTestModule(t, "readonly", pm)
	rec := do(m, "GET", "/versions", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "v18.19.0") {
		t.Fatalf("versions endpoint wrong: %d %s", rec.Code, rec.Body.String())
	}
}

func TestVersionsEmptyReturnsArray(t *testing.T) {
	m, _ := newTestModule(t, "readonly", &mockPM{})
	rec := do(m, "GET", "/versions", "", nil)
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty versions should be [], got %q", rec.Body.String())
	}
}

func TestListEmptyReturnsArray(t *testing.T) {
	m, _ := newTestModule(t, "readonly", &mockPM{})
	rec := do(m, "GET", "/projects", "", nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list should be [], got %d %q", rec.Code, rec.Body.String())
	}
}

// seedProject 经由真实 create handler 落一条项目,返回其 id 字符串。
func seedProject(t *testing.T, m *Module) string {
	t.Helper()
	body := `{"name":"web","directory":"web","command":"node app.js","port":3000}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed failed: %d %s", rec.Code, rec.Body.String())
	}
	return "1"
}
