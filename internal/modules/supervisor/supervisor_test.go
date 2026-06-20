package supervisor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockController 记录调用并返回可控结果,隔离真实 supervisorctl/文件系统。
type mockController struct {
	writes   []string // name 写过配置
	removes  []string
	actions  []string // "verb name"
	reloads  int
	avail    error
	writeErr error
	lastCfg  string
	configs  map[string]string // name -> 落盘配置内容,供 ReadConfig 回读
}

func (c *mockController) WriteConfig(_, name, content string) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	c.writes = append(c.writes, name)
	c.lastCfg = content
	if c.configs == nil {
		c.configs = map[string]string{}
	}
	c.configs[name] = content
	return nil
}
func (c *mockController) ReadConfig(_, name string) (string, error) {
	return c.configs[name], nil
}
func (c *mockController) RemoveConfig(_, name string) error {
	c.removes = append(c.removes, name)
	return nil
}
func (c *mockController) Reload() error { c.reloads++; return nil }
func (c *mockController) Action(verb, name string) (string, error) {
	c.actions = append(c.actions, verb+" "+name)
	return "ok", nil
}
func (c *mockController) Status(name string) (string, error) { return "RUNNING " + name, nil }
func (c *mockController) TailLog(name string, _ int, _ bool) (string, error) {
	return "log " + name, nil
}
func (c *mockController) Available() error { return c.avail }

func newTestModule(t *testing.T, role string, ctl Controller) (*Module, *int) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	audited := new(int)
	m := New(st, ctl, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	})
	return m, audited
}

func do(m *Module, method, target string, body string, headers map[string]string) *httptest.ResponseRecorder {
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
	m, _ := newTestModule(t, "admin", &mockController{})
	if m.Meta().ID != "supervisor" || m.Meta().AlwaysOn {
		t.Errorf("must be id=supervisor, not AlwaysOn, got %+v", m.Meta())
	}
	if m.Meta().Category != "系统" {
		t.Errorf("category should be 系统, got %q", m.Meta().Category)
	}
}

func TestHealthCheckUnavailable(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockController{avail: http.ErrNotSupported})
	if m.HealthCheck() == nil {
		t.Error("HealthCheck should fail when supervisorctl unavailable")
	}
}

func TestCreateHappyPath(t *testing.T) {
	ctl := &mockController{}
	m, audited := newTestModule(t, "admin", ctl)
	body := `{"name":"web","command":"/bin/run","directory":"/opt/web","auto_restart":true,"numprocs":2}`
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(ctl.writes) != 1 || ctl.writes[0] != "web" {
		t.Fatalf("expected config write for web, got %v", ctl.writes)
	}
	if ctl.reloads != 1 {
		t.Fatalf("expected 1 reload, got %d", ctl.reloads)
	}
	if !strings.Contains(ctl.lastCfg, "[program:web]") || !strings.Contains(ctl.lastCfg, "numprocs=2") {
		t.Fatalf("rendered config wrong: %s", ctl.lastCfg)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestCreateUserPriorityPersists(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	body := `{"name":"web","command":"/bin/run","directory":"/opt/web","numprocs":1,"user":"www","priority":500}`
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"user":"www"`) || !strings.Contains(rec.Body.String(), `"priority":500`) {
		t.Fatalf("response missing user/priority: %s", rec.Body.String())
	}
	if !strings.Contains(ctl.lastCfg, "user=www") || !strings.Contains(ctl.lastCfg, "priority=500") {
		t.Fatalf("rendered config missing user/priority: %s", ctl.lastCfg)
	}
	list := do(m, "GET", "/programs", "", nil)
	if !strings.Contains(list.Body.String(), `"user":"www"`) || !strings.Contains(list.Body.String(), `"priority":500`) {
		t.Fatalf("list missing user/priority: %s", list.Body.String())
	}
}

func TestCreateDefaultsPriorityAndOmitsUser(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	body := `{"name":"web","command":"/bin/run","directory":"/opt/web","numprocs":1}`
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"priority":999`) {
		t.Fatalf("omitted priority should default to 999: %s", rec.Body.String())
	}
	if !strings.Contains(ctl.lastCfg, "priority=999") {
		t.Fatalf("rendered config should have priority=999: %s", ctl.lastCfg)
	}
	if strings.Contains(ctl.lastCfg, "user=") {
		t.Fatalf("empty user must not render user= line: %s", ctl.lastCfg)
	}
}

func TestCreateRejectsInvalidUser(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	body := `{"name":"web","command":"/bin/run","directory":"/opt","numprocs":1,"user":"Bad User!"}`
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid user should 400, got %d", rec.Code)
	}
	if len(ctl.writes) != 0 {
		t.Fatalf("must not write config on invalid user, got %v", ctl.writes)
	}
}

func TestCreateRejectsInvalidPriority(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	body := `{"name":"web","command":"/bin/run","directory":"/opt","numprocs":1,"priority":10000}`
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid priority should 400, got %d", rec.Code)
	}
	if len(ctl.writes) != 0 {
		t.Fatalf("must not write config on invalid priority, got %v", ctl.writes)
	}
}

func TestCreateRejectsInjectionName(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	body := `{"name":"web;rm -rf /","command":"/bin/run","directory":"/opt","numprocs":1}`
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection name should 400, got %d", rec.Code)
	}
	if len(ctl.writes) != 0 {
		t.Fatalf("must not write config on invalid input, got %v", ctl.writes)
	}
}

func TestCreateRejectsInjectionCommand(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	body := "{\"name\":\"web\",\"command\":\"run\\nmalicious=1\",\"directory\":\"/opt\",\"numprocs\":1}"
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("newline command should 400, got %d", rec.Code)
	}
}

func TestCreateRejectsRelativeDir(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	body := `{"name":"web","command":"/bin/run","directory":"relative","numprocs":1}`
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("relative dir should 400, got %d", rec.Code)
	}
}

func TestCreateRequiresAdmin(t *testing.T) {
	ctl := &mockController{}
	m, audited := newTestModule(t, "readonly", ctl)
	body := `{"name":"web","command":"/bin/run","directory":"/opt","numprocs":1}`
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create should 403, got %d", rec.Code)
	}
	if *audited != 0 || len(ctl.writes) != 0 {
		t.Fatal("forbidden create must not audit or write")
	}
}

// TestCreateOperatorForbidden 复现并锁定提权漏洞修复:operator 指定任意启动命令添加守护程序
// 必须 403 —— 否则 operator 可借此让命令以 supervisor 属主(通常 root)执行而提权。
func TestCreateOperatorForbidden(t *testing.T) {
	ctl := &mockController{}
	m, audited := newTestModule(t, "operator", ctl)
	body := `{"name":"pwn","command":"/bin/sh -c id","directory":"/opt","numprocs":1}`
	rec := do(m, "POST", "/programs", body, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator create (arbitrary command) must 403, got %d", rec.Code)
	}
	if *audited != 0 || len(ctl.writes) != 0 {
		t.Fatal("forbidden operator create must not audit or write")
	}
}

// TestOperatorCanStartStop 确认收紧 create 后,operator 仍可对已有程序执行 start/stop/restart。
func TestOperatorCanStartStop(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "operator", ctl)
	id := seedProgram(t, m)
	if rec := do(m, "POST", "/programs/"+id+"/restart", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("operator restart should 200, got %d", rec.Code)
	}
	if rec := do(m, "POST", "/programs/"+id+"/start", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("operator start should 200, got %d", rec.Code)
	}
	rec := do(m, "POST", "/programs/"+id+"/stop", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("operator stop (confirmed) should 200, got %d", rec.Code)
	}
}

func TestStopRequiresConfirm(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "operator", ctl)
	id := seedProgram(t, m)
	rec := do(m, "POST", "/programs/"+id+"/stop", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("stop without confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "POST", "/programs/"+id+"/stop", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("stop with confirm should 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRestartNoConfirmNeeded(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "operator", ctl)
	id := seedProgram(t, m)
	rec := do(m, "POST", "/programs/"+id+"/restart", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("restart should 200, got %d", rec.Code)
	}
}

func TestDeleteRequiresAdminAndConfirm(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "operator", ctl)
	id := seedProgram(t, m)

	// 缺确认头:428(在 RBAC 之前)。
	rec := do(m, "DELETE", "/programs/"+id, "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	// 有确认但 operator 角色:403。
	rec = do(m, "DELETE", "/programs/"+id, "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator delete should 403, got %d", rec.Code)
	}
}

func TestDeleteAdminConfirmedRemovesConfig(t *testing.T) {
	ctl := &mockController{}
	m, audited := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	*audited = 0
	rec := do(m, "DELETE", "/programs/"+id, "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin confirmed delete should 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(ctl.removes) != 1 {
		t.Fatalf("expected config removal, got %v", ctl.removes)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestPutSettingsRequiresAdmin(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "operator", ctl)
	rec := do(m, "PUT", "/settings", `{"conf_dir":"/a","log_dir":"/b"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator put settings should 403, got %d", rec.Code)
	}
}

func TestPutSettingsValidatesPaths(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	rec := do(m, "PUT", "/settings", `{"conf_dir":"relative","log_dir":"/b"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-absolute conf_dir should 400, got %d", rec.Code)
	}
}

func TestSettingsRoundTripViaAPI(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	rec := do(m, "PUT", "/settings", `{"conf_dir":"/custom/conf","log_dir":"/custom/log"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin put settings should 200, got %d", rec.Code)
	}
	rec = do(m, "GET", "/settings", "", nil)
	if !strings.Contains(rec.Body.String(), "/custom/conf") {
		t.Fatalf("settings not persisted: %s", rec.Body.String())
	}
}

func TestListEmptyReturnsArray(t *testing.T) {
	m, _ := newTestModule(t, "readonly", &mockController{})
	rec := do(m, "GET", "/programs", "", nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list should be [], got %d %q", rec.Code, rec.Body.String())
	}
}

func TestUpdateHappyPath(t *testing.T) {
	ctl := &mockController{}
	m, audited := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	*audited = 0
	ctl.reloads = 0
	body := `{"name":"web","command":"/bin/run2","directory":"/opt/web2","auto_restart":false,"numprocs":3}`
	rec := do(m, "PUT", "/programs/"+id, body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("update should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// 配置被重写、reload 触发、新值生效。
	if len(ctl.writes) == 0 || ctl.writes[len(ctl.writes)-1] != "web" {
		t.Fatalf("expected config rewrite for web, got %v", ctl.writes)
	}
	if ctl.reloads != 1 {
		t.Fatalf("expected 1 reload, got %d", ctl.reloads)
	}
	if !strings.Contains(ctl.lastCfg, "/bin/run2") || !strings.Contains(ctl.lastCfg, "numprocs=3") {
		t.Fatalf("rendered config not updated: %s", ctl.lastCfg)
	}
	if !strings.Contains(rec.Body.String(), "/opt/web2") {
		t.Fatalf("response missing updated directory: %s", rec.Body.String())
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestUpdateRenameRemovesOldConfig(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m) // name "web"
	body := `{"name":"app","command":"/bin/run","directory":"/opt/web","auto_restart":true,"numprocs":1}`
	rec := do(m, "PUT", "/programs/"+id, body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename update should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(ctl.removes) != 1 || ctl.removes[0] != "web" {
		t.Fatalf("rename must remove old config 'web', got %v", ctl.removes)
	}
	if ctl.writes[len(ctl.writes)-1] != "app" {
		t.Fatalf("rename must write new config 'app', got %v", ctl.writes)
	}
}

func TestUpdateRejectsInjectionCommand(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	writesBefore := len(ctl.writes)
	body := "{\"name\":\"web\",\"command\":\"run\\nmalicious=1\",\"directory\":\"/opt\",\"numprocs\":1}"
	rec := do(m, "PUT", "/programs/"+id, body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("newline command should 400, got %d", rec.Code)
	}
	if len(ctl.writes) != writesBefore {
		t.Fatalf("must not rewrite config on invalid input, got %v", ctl.writes)
	}
}

func TestUpdateRejectsInjectionName(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	body := `{"name":"web;rm -rf /","command":"/bin/run","directory":"/opt","numprocs":1}`
	rec := do(m, "PUT", "/programs/"+id, body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection name should 400, got %d", rec.Code)
	}
}

func TestUpdateRejectsRelativeDir(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	body := `{"name":"web","command":"/bin/run","directory":"relative","numprocs":1}`
	rec := do(m, "PUT", "/programs/"+id, body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("relative dir should 400, got %d", rec.Code)
	}
}

func TestUpdateNotFound(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	body := `{"name":"web","command":"/bin/run","directory":"/opt","numprocs":1}`
	rec := do(m, "PUT", "/programs/999", body, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update missing program should 404, got %d", rec.Code)
	}
}

// TestUpdateRequiresAdmin 锁定提权防线:operator 编辑(可改启动命令)必须 403,不得落配置。
func TestUpdateRequiresAdmin(t *testing.T) {
	ctl := &mockController{}
	m, audited := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	*audited = 0
	writesBefore := len(ctl.writes)

	op := cloneRole(m, "operator")
	body := `{"name":"pwn","command":"/bin/sh -c id","directory":"/opt","numprocs":1}`
	rec := do(op, "PUT", "/programs/"+id, body, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator update (arbitrary command) must 403, got %d", rec.Code)
	}
	if *audited != 0 || len(ctl.writes) != writesBefore {
		t.Fatal("forbidden update must not audit or write config")
	}
	// 元数据未被改动。
	if p, _ := m.ss.get(1); p.Name != "web" || p.Command != "/bin/run" {
		t.Fatalf("forbidden update must not mutate record, got %+v", p)
	}
}

func TestGetConfigReturnsContent(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "readonly", ctl)
	seedProgram(t, cloneRole(m, "admin")) // create 落配置,name "web"
	rec := do(m, "GET", "/programs/1/config", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get config should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"content"`) || !strings.Contains(rec.Body.String(), "[program:web]") {
		t.Fatalf("get config body wrong: %s", rec.Body.String())
	}
}

func TestGetConfigNotFound(t *testing.T) {
	m, _ := newTestModule(t, "readonly", &mockController{})
	rec := do(m, "GET", "/programs/999/config", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get config unknown id should 404, got %d", rec.Code)
	}
}

func TestPutConfigAdminConfirmed(t *testing.T) {
	ctl := &mockController{}
	m, audited := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	*audited = 0
	ctl.reloads = 0
	body := `{"content":"[program:web]\ncommand=/bin/edited\n"}`
	rec := do(m, "PUT", "/programs/"+id+"/config", body, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put config (admin confirmed) should 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if ctl.configs["web"] != "[program:web]\ncommand=/bin/edited\n" {
		t.Fatalf("controller did not receive new content, got %q", ctl.configs["web"])
	}
	if ctl.reloads != 1 {
		t.Fatalf("expected 1 reload, got %d", ctl.reloads)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestPutConfigRequiresAdmin(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	writesBefore := len(ctl.writes)
	op := cloneRole(m, "operator")
	body := `{"content":"[program:web]\n"}`
	rec := do(op, "PUT", "/programs/"+id+"/config", body, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator put config should 403, got %d", rec.Code)
	}
	if len(ctl.writes) != writesBefore {
		t.Fatalf("forbidden put config must not write, got %v", ctl.writes)
	}
}

func TestPutConfigRequiresConfirm(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	body := `{"content":"[program:web]\n"}`
	rec := do(m, "PUT", "/programs/"+id+"/config", body, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("put config without confirm should 428, got %d", rec.Code)
	}
}

func TestPutConfigRejectsEmpty(t *testing.T) {
	ctl := &mockController{}
	m, _ := newTestModule(t, "admin", ctl)
	id := seedProgram(t, m)
	rec := do(m, "PUT", "/programs/"+id+"/config", `{"content":""}`, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty content should 400, got %d", rec.Code)
	}
}

func TestPutConfigNotFound(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockController{})
	body := `{"content":"[program:web]\n"}`
	rec := do(m, "PUT", "/programs/999/config", body, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("put config unknown id should 404, got %d", rec.Code)
	}
}

// cloneRole 在同一 DB/Controller 上复制一个不同角色的 Module 视图,用于跨角色访问已有数据。
func cloneRole(m *Module, role string) *Module {
	return &Module{
		ss:  m.ss,
		ctl: m.ctl,
		deps: Deps{
			Principal: func(*http.Request) (int64, string) { return 2, role },
			Audit:     func(*int64, string, string, string) {},
		},
	}
}

// seedProgram 以 admin 身份经真实 create handler 落一条程序(创建需 admin),返回其 id 字符串。
func seedProgram(t *testing.T, m *Module) string {
	t.Helper()
	body := `{"name":"web","command":"/bin/run","directory":"/opt/web","auto_restart":true,"numprocs":1}`
	rec := do(cloneRole(m, "admin"), "POST", "/programs", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed failed: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := m.ss.get(1); err != nil {
		t.Fatalf("seed get: %v", err)
	}
	return "1"
}
