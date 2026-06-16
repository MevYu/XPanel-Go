package mysqlrepl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// mockBackend 记录 exec 语句并按预设返回 queryRow,供断言注入拒绝/语句正确/状态解析。
type mockBackend struct {
	execs []string
	// rows: SQL → 单行结果。未命中返回 nil(无行)。
	rows map[string]map[string]string
}

func (b *mockBackend) queryRow(_ context.Context, q string, _ ...any) (map[string]string, error) {
	if b.rows == nil {
		return nil, nil
	}
	return b.rows[q], nil
}
func (b *mockBackend) exec(_ context.Context, q string, _ ...any) error {
	b.execs = append(b.execs, q)
	return nil
}
func (b *mockBackend) close() error { return nil }

func newTestModule(t *testing.T, role string, audited *int) (*Module, *mockBackend) {
	t.Helper()
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 7, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	}
	m := New("test-secret", newTestStore(t), deps)
	be := &mockBackend{rows: map[string]map[string]string{}}
	m.connect = func(context.Context, connConfig) (mysqlBackend, error) { return be, nil }
	return m, be
}

func router(m *Module) chi.Router {
	r := chi.NewRouter()
	m.Routes(r)
	return r
}

func do(r chi.Router, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestMeta(t *testing.T) {
	m, _ := newTestModule(t, "admin", new(int))
	meta := m.Meta()
	if meta.ID != "mysqlrepl" || meta.Name != "MySQL主从" || meta.Category != "数据库" || meta.AlwaysOn {
		t.Errorf("unexpected meta %+v", meta)
	}
	nav := m.Nav()
	if len(nav) != 1 || nav[0].Path != "/mysqlrepl" || nav[0].Icon != "git-branch" {
		t.Errorf("unexpected nav %+v", nav)
	}
	if err := m.HealthCheck(); err != nil {
		t.Errorf("HealthCheck should pass: %v", err)
	}
}

func TestNonAdminForbidden(t *testing.T) {
	for _, role := range []string{"readonly", "operator"} {
		audited := 0
		m, be := newTestModule(t, role, &audited)
		r := router(m)
		cases := []struct{ method, path, body string }{
			{"GET", "/settings", ""},
			{"PUT", "/settings", `{}`},
			{"GET", "/master/status", ""},
			{"POST", "/master/repl-user", `{"repl_user":"repl","repl_password":"p"}`},
			{"GET", "/slave/status", ""},
			{"POST", "/slave/configure", `{"repl_user":"repl","repl_password":"p","master_host":"h","master_port":3306}`},
			{"POST", "/slave/start", ""},
			{"POST", "/slave/stop", ""},
			{"POST", "/slave/reset", ""},
		}
		for _, c := range cases {
			rec := do(r, c.method, c.path, c.body, nil)
			if rec.Code != http.StatusForbidden {
				t.Errorf("role %s %s %s = %d, want 403", role, c.method, c.path, rec.Code)
			}
		}
		if len(be.execs) != 0 {
			t.Errorf("forbidden must not exec, got %v", be.execs)
		}
		if audited != 0 {
			t.Errorf("forbidden must not audit, got %d", audited)
		}
	}
}

func TestMasterStatusHandler(t *testing.T) {
	m, be := newTestModule(t, "admin", new(int))
	be.rows["SHOW MASTER STATUS"] = map[string]string{"File": "binlog.000005", "Position": "1234"}
	rec := do(router(m), "GET", "/master/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("master status = %d, body %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "binlog.000005") || !strings.Contains(body, "1234") {
		t.Errorf("master status body = %s", body)
	}
}

func TestSlaveStatusHandler(t *testing.T) {
	m, be := newTestModule(t, "admin", new(int))
	be.rows["SHOW SLAVE STATUS"] = map[string]string{
		"Slave_IO_Running": "Yes", "Slave_SQL_Running": "Yes", "Seconds_Behind_Master": "3",
	}
	rec := do(router(m), "GET", "/slave/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("slave status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"healthy":true`) || !strings.Contains(body, `"seconds_behind":3`) {
		t.Errorf("slave status body = %s", body)
	}
}

func TestReplUserHandler(t *testing.T) {
	audited := 0
	m, be := newTestModule(t, "admin", &audited)
	rec := do(router(m), "POST", "/master/repl-user", `{"repl_user":"repl","repl_password":"p@ss","slave_host":"10.0.0.2"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("repl-user = %d, body %s", rec.Code, rec.Body)
	}
	if len(be.execs) != 2 || !strings.HasPrefix(be.execs[0], "CREATE USER IF NOT EXISTS `repl`") {
		t.Errorf("execs = %v", be.execs)
	}
	if audited != 1 {
		t.Errorf("repl-user should audit once, got %d", audited)
	}
}

func TestReplUserRejectsInjection(t *testing.T) {
	audited := 0
	m, be := newTestModule(t, "admin", &audited)
	rec := do(router(m), "POST", "/master/repl-user", `{"repl_user":"bad;user","repl_password":"p"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad repl_user = %d, want 400", rec.Code)
	}
	if len(be.execs) != 0 {
		t.Errorf("must not reach SQL: %v", be.execs)
	}
	if audited != 0 {
		t.Errorf("rejected must not audit, got %d", audited)
	}
}

func TestReplUserPasswordNotInAudit(t *testing.T) {
	var auditDetail string
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 1, "admin" },
		Audit:     func(_ *int64, _, detail, _ string) { auditDetail = detail },
	}
	m := New("s", newTestStore(t), deps)
	be := &mockBackend{}
	m.connect = func(context.Context, connConfig) (mysqlBackend, error) { return be, nil }
	do(router(m), "POST", "/master/repl-user", `{"repl_user":"repl","repl_password":"sup3rSecret"}`, nil)
	if strings.Contains(auditDetail, "sup3rSecret") {
		t.Errorf("audit detail leaks password: %q", auditDetail)
	}
}

func TestConfigureSlaveHandler(t *testing.T) {
	audited := 0
	m, be := newTestModule(t, "admin", &audited)
	body := `{"master_host":"10.0.0.1","master_port":3306,"repl_user":"repl","repl_password":"p","master_log_file":"binlog.000003","master_log_pos":154}`
	rec := do(router(m), "POST", "/slave/configure", body, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("configure = %d, body %s", rec.Code, rec.Body)
	}
	if len(be.execs) != 2 || !strings.HasPrefix(be.execs[0], "CHANGE MASTER TO") || be.execs[1] != "START SLAVE" {
		t.Errorf("execs = %v", be.execs)
	}
	if audited != 1 {
		t.Errorf("configure should audit, got %d", audited)
	}
}

func TestConfigureSlaveValidatesPort(t *testing.T) {
	m, be := newTestModule(t, "admin", new(int))
	body := `{"master_host":"h","master_port":0,"repl_user":"repl","repl_password":"p"}`
	rec := do(router(m), "POST", "/slave/configure", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("port 0 = %d, want 400", rec.Code)
	}
	if len(be.execs) != 0 {
		t.Errorf("must not exec: %v", be.execs)
	}
}

func TestStartSlaveNoConfirm(t *testing.T) {
	audited := 0
	m, be := newTestModule(t, "admin", &audited)
	// start 非危险:无确认头即可
	rec := do(router(m), "POST", "/slave/start", "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("start = %d", rec.Code)
	}
	if len(be.execs) != 1 || be.execs[0] != "START SLAVE" {
		t.Errorf("execs = %v", be.execs)
	}
	if audited != 1 {
		t.Errorf("start should audit, got %d", audited)
	}
}

func TestStopSlaveRequiresConfirm(t *testing.T) {
	audited := 0
	m, be := newTestModule(t, "admin", &audited)
	r := router(m)
	rec := do(r, "POST", "/slave/stop", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("stop without confirm = %d, want 428", rec.Code)
	}
	if len(be.execs) != 0 || audited != 0 {
		t.Errorf("unconfirmed stop must not exec/audit: execs=%v audited=%d", be.execs, audited)
	}
	rec = do(r, "POST", "/slave/stop", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent || be.execs[0] != "STOP SLAVE" {
		t.Errorf("confirmed stop code=%d execs=%v", rec.Code, be.execs)
	}
	if audited != 1 {
		t.Errorf("confirmed stop should audit, got %d", audited)
	}
}

func TestResetSlaveRequiresConfirm(t *testing.T) {
	m, be := newTestModule(t, "admin", new(int))
	r := router(m)
	rec := do(r, "POST", "/slave/reset", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("reset without confirm = %d, want 428", rec.Code)
	}
	if len(be.execs) != 0 {
		t.Error("unconfirmed reset must not exec")
	}
	rec = do(r, "POST", "/slave/reset", "", map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed reset = %d", rec.Code)
	}
	if len(be.execs) != 2 || be.execs[0] != "STOP SLAVE" || be.execs[1] != "RESET SLAVE ALL" {
		t.Errorf("reset execs = %v", be.execs)
	}
}

func TestSettingsGetMasksPassword(t *testing.T) {
	m, _ := newTestModule(t, "admin", new(int))
	r := router(m)
	do(r, "PUT", "/settings", `{"master_password":"secret","master_port":13306}`, nil)
	rec := do(r, "GET", "/settings", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get settings = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret") {
		t.Errorf("GET /settings leaks password: %s", body)
	}
	if !strings.Contains(body, "13306") || !strings.Contains(body, "master") {
		t.Errorf("settings body missing fields: %s", body)
	}
}
