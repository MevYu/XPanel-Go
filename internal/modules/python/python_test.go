package python

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockProv 记录 venv/依赖安装调用。
type mockProv struct {
	venvs       []string // venvDir
	installs    []string // venvDir
	venvErr     error
	installErr  error
	lastInterp  string
	lastReqPath string
}

func (p *mockProv) CreateVenv(interpreter, venvDir string) error {
	p.lastInterp = interpreter
	p.venvs = append(p.venvs, venvDir)
	return p.venvErr
}
func (p *mockProv) InstallRequirements(venvDir, reqPath string) error {
	p.installs = append(p.installs, venvDir)
	p.lastReqPath = reqPath
	return p.installErr
}

// mockRunner 记录进程管理调用。
type mockRunner struct {
	applies  []string // name
	removes  []string
	actions  []string // "verb name"
	avail    error
	applyErr error
	lastArgv []string
}

func (rn *mockRunner) Apply(name, _ string, argv []string) error {
	rn.applies = append(rn.applies, name)
	rn.lastArgv = argv
	return rn.applyErr
}
func (rn *mockRunner) Remove(name string) error { rn.removes = append(rn.removes, name); return nil }
func (rn *mockRunner) Action(verb, name string) (string, error) {
	rn.actions = append(rn.actions, verb+" "+name)
	return "ok", nil
}
func (rn *mockRunner) Status(name string) (string, error)      { return "RUNNING " + name, nil }
func (rn *mockRunner) Logs(name string, _ int) (string, error) { return "log " + name, nil }
func (rn *mockRunner) Available() error                        { return rn.avail }

func newTestModule(t *testing.T, role string, prov Provisioner, rn Runner) (*Module, *int) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	audited := new(int)
	m := New(st, prov, func(Settings) Runner { return rn }, Deps{
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

const validBody = `{"name":"api","interpreter":"python3.11","start_kind":"gunicorn","app_target":"wsgi:app","port":8000,"workers":3}`

func seedProject(t *testing.T, m *Module) string {
	t.Helper()
	rec := do(m, "POST", "/projects", validBody, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed failed: %d %s", rec.Code, rec.Body.String())
	}
	return "1"
}

func TestMetaSwitchable(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockProv{}, &mockRunner{})
	meta := m.Meta()
	if meta.ID != "python" || meta.AlwaysOn {
		t.Errorf("must be id=python, not AlwaysOn, got %+v", meta)
	}
	if meta.Category != "网站" {
		t.Errorf("category should be 网站, got %q", meta.Category)
	}
}

func TestCreateHappyPath(t *testing.T) {
	prov := &mockProv{}
	rn := &mockRunner{}
	m, audited := newTestModule(t, "operator", prov, rn)
	rec := do(m, "POST", "/projects", validBody, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(prov.venvs) != 1 || prov.lastInterp != "python3.11" {
		t.Fatalf("expected venv create with python3.11, got %v interp=%q", prov.venvs, prov.lastInterp)
	}
	if len(rn.applies) != 1 || rn.applies[0] != "api" {
		t.Fatalf("expected runner apply for api, got %v", rn.applies)
	}
	if strings.Join(rn.lastArgv, " ") != "/www/python/venv/api/bin/gunicorn --workers 3 --bind 0.0.0.0:8000 wsgi:app" {
		t.Fatalf("argv wrong: %v", rn.lastArgv)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestCreateUsesDefaultInterpreter(t *testing.T) {
	prov := &mockProv{}
	m, _ := newTestModule(t, "operator", prov, &mockRunner{})
	body := `{"name":"api","start_kind":"script","app_target":"run.py"}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if prov.lastInterp != defaultInterpreter {
		t.Fatalf("expected default interpreter %q, got %q", defaultInterpreter, prov.lastInterp)
	}
}

func TestCreateRejectsInjectionName(t *testing.T) {
	prov := &mockProv{}
	rn := &mockRunner{}
	m, _ := newTestModule(t, "operator", prov, rn)
	body := `{"name":"api;rm -rf /","interpreter":"python3","start_kind":"script","app_target":"run.py"}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection name should 400, got %d", rec.Code)
	}
	if len(prov.venvs) != 0 || len(rn.applies) != 0 {
		t.Fatal("must not provision/apply on invalid input")
	}
}

func TestCreateRejectsInjectionAppTarget(t *testing.T) {
	m, _ := newTestModule(t, "operator", &mockProv{}, &mockRunner{})
	body := `{"name":"api","interpreter":"python3","start_kind":"gunicorn","app_target":"wsgi:app$(id)","port":8000}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection app_target should 400, got %d", rec.Code)
	}
}

func TestCreateRejectsBadInterpreter(t *testing.T) {
	m, _ := newTestModule(t, "operator", &mockProv{}, &mockRunner{})
	body := `{"name":"api","interpreter":"python2; rm","start_kind":"script","app_target":"run.py"}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad interpreter should 400, got %d", rec.Code)
	}
}

func TestCreateRejectsBadPortForServer(t *testing.T) {
	m, _ := newTestModule(t, "operator", &mockProv{}, &mockRunner{})
	body := `{"name":"api","interpreter":"python3","start_kind":"uvicorn","app_target":"main:app","port":0}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("uvicorn without port should 400, got %d", rec.Code)
	}
}

func TestCreateRequiresWriter(t *testing.T) {
	prov := &mockProv{}
	m, audited := newTestModule(t, "readonly", prov, &mockRunner{})
	rec := do(m, "POST", "/projects", validBody, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create should 403, got %d", rec.Code)
	}
	if *audited != 0 || len(prov.venvs) != 0 {
		t.Fatal("forbidden create must not audit or provision")
	}
}

func TestCreateRollsBackOnVenvFailure(t *testing.T) {
	prov := &mockProv{venvErr: http.ErrNotSupported}
	m, _ := newTestModule(t, "operator", prov, &mockRunner{})
	rec := do(m, "POST", "/projects", validBody, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("venv failure should 500, got %d", rec.Code)
	}
	if list, _ := m.ps.list(); len(list) != 0 {
		t.Fatalf("metadata must be rolled back on venv failure, got %d rows", len(list))
	}
}

func TestInstallRequiresWriter(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockProv{}, &mockRunner{})
	seedProject(t, m)
	roM, _ := cloneRole(t, m, "readonly")
	rec := do(roM, "POST", "/projects/1/requirements", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly install should 403, got %d", rec.Code)
	}
}

func TestInstallHappyPath(t *testing.T) {
	prov := &mockProv{}
	m, audited := newTestModule(t, "operator", prov, &mockRunner{})
	seedProject(t, m)
	*audited = 0
	rec := do(m, "POST", "/projects/1/requirements", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("install should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(prov.installs) != 1 || prov.lastReqPath != "/www/python/api/requirements.txt" {
		t.Fatalf("expected install with project requirements.txt, got %v path=%q", prov.installs, prov.lastReqPath)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestStopRequiresConfirm(t *testing.T) {
	rn := &mockRunner{}
	m, _ := newTestModule(t, "operator", &mockProv{}, rn)
	seedProject(t, m)
	rec := do(m, "POST", "/projects/1/stop", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("stop without confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "POST", "/projects/1/stop", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("stop with confirm should 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRestartNoConfirmNeeded(t *testing.T) {
	m, _ := newTestModule(t, "operator", &mockProv{}, &mockRunner{})
	seedProject(t, m)
	rec := do(m, "POST", "/projects/1/restart", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("restart should 200, got %d", rec.Code)
	}
}

func TestDeleteRequiresAdminAndConfirm(t *testing.T) {
	m, _ := newTestModule(t, "operator", &mockProv{}, &mockRunner{})
	seedProject(t, m)
	// 缺确认头:428(在 RBAC 之前)。
	rec := do(m, "DELETE", "/projects/1", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	// 有确认但 operator 角色:403。
	rec = do(m, "DELETE", "/projects/1", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator delete should 403, got %d", rec.Code)
	}
}

func TestDeleteAdminConfirmedRemovesUnit(t *testing.T) {
	rn := &mockRunner{}
	m, audited := newTestModule(t, "admin", &mockProv{}, rn)
	seedProject(t, m)
	*audited = 0
	rec := do(m, "DELETE", "/projects/1", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin confirmed delete should 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(rn.removes) != 1 {
		t.Fatalf("expected unit removal, got %v", rn.removes)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestPutSettingsRequiresAdmin(t *testing.T) {
	m, _ := newTestModule(t, "operator", &mockProv{}, &mockRunner{})
	body := `{"project_root":"/a","venv_root":"/b","interpreter":"python3","conf_dir":"/c","log_dir":"/d"}`
	rec := do(m, "PUT", "/settings", body, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator put settings should 403, got %d", rec.Code)
	}
}

func TestPutSettingsValidatesPaths(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockProv{}, &mockRunner{})
	body := `{"project_root":"relative","venv_root":"/b","interpreter":"python3","conf_dir":"/c","log_dir":"/d"}`
	rec := do(m, "PUT", "/settings", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-absolute project_root should 400, got %d", rec.Code)
	}
}

func TestPutSettingsValidatesInterpreter(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockProv{}, &mockRunner{})
	body := `{"project_root":"/a","venv_root":"/b","interpreter":"python2; rm","conf_dir":"/c","log_dir":"/d"}`
	rec := do(m, "PUT", "/settings", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad interpreter should 400, got %d", rec.Code)
	}
}

func TestSettingsRoundTripViaAPI(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockProv{}, &mockRunner{})
	body := `{"project_root":"/srv/py","venv_root":"/srv/venv","interpreter":"python3.12","conf_dir":"/c","log_dir":"/d"}`
	rec := do(m, "PUT", "/settings", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin put settings should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = do(m, "GET", "/settings", "", nil)
	if !strings.Contains(rec.Body.String(), "/srv/py") || !strings.Contains(rec.Body.String(), "python3.12") {
		t.Fatalf("settings not persisted: %s", rec.Body.String())
	}
}

func TestSettingsAffectCreatePaths(t *testing.T) {
	prov := &mockProv{}
	m, _ := newTestModule(t, "admin", prov, &mockRunner{})
	body := `{"project_root":"/srv/py","venv_root":"/srv/venv","interpreter":"python3","conf_dir":"/c","log_dir":"/d"}`
	if rec := do(m, "PUT", "/settings", body, nil); rec.Code != http.StatusOK {
		t.Fatalf("put settings failed: %d", rec.Code)
	}
	rec := do(m, "POST", "/projects", validBody, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create after settings change should 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(prov.venvs) != 1 || prov.venvs[0] != "/srv/venv/api" {
		t.Fatalf("venv dir should derive from configured venv_root, got %v", prov.venvs)
	}
}

func TestListEmptyReturnsArray(t *testing.T) {
	m, _ := newTestModule(t, "readonly", &mockProv{}, &mockRunner{})
	rec := do(m, "GET", "/projects", "", nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list should be [], got %d %q", rec.Code, rec.Body.String())
	}
}

// cloneRole 在同一 DB 上复制一个不同角色的 Module 视图,用于跨角色访问已有数据。
func cloneRole(t *testing.T, m *Module, role string) (*Module, *int) {
	t.Helper()
	audited := new(int)
	clone := &Module{
		ps:    m.ps,
		prov:  m.prov,
		mkrun: m.mkrun,
		deps: Deps{
			Principal: func(*http.Request) (int64, string) { return 2, role },
			Audit:     func(*int64, string, string, string) { *audited++ },
		},
	}
	return clone, audited
}
