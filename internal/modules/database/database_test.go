package database

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// mockSQL 记录收到的 SQL 语句,供断言注入是否被拒/语句是否正确。
type mockSQL struct {
	execs   []string
	queries []string
	rows    []string
}

func (m *mockSQL) queryStrings(_ context.Context, q string, _ ...any) ([]string, error) {
	m.queries = append(m.queries, q)
	return m.rows, nil
}
func (m *mockSQL) exec(_ context.Context, q string, _ ...any) error {
	m.execs = append(m.execs, q)
	return nil
}
func (m *mockSQL) ping(context.Context) error { return nil }
func (m *mockSQL) close() error               { return nil }

// mockRedis 记录调用。
type mockRedis struct{ flushed bool }

func (m *mockRedis) info(context.Context) (string, error)  { return "redis_version:7.0\n", nil }
func (m *mockRedis) dbSize(context.Context) (int64, error) { return 42, nil }
func (m *mockRedis) flushDB(context.Context) error         { m.flushed = true; return nil }
func (m *mockRedis) close() error                          { return nil }

func newTestModule(t *testing.T, role string, audited *int) (*Module, *mockSQL, *mockRedis) {
	t.Helper()
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 7, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	}
	m := New("test-secret", newTestStore(t), deps)
	sql := &mockSQL{}
	redis := &mockRedis{}
	m.mysqlConn = func(context.Context, Settings) (sqlBackend, error) { return sql, nil }
	m.pgConn = func(context.Context, Settings) (sqlBackend, error) { return sql, nil }
	m.redisConn = func(context.Context, Settings) (redisBackend, error) { return redis, nil }
	return m, sql, redis
}

func router(m *Module) chi.Router {
	r := chi.NewRouter()
	m.Routes(r)
	return r
}

func do(r chi.Router, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestMeta(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	meta := m.Meta()
	if meta.ID != "database" || meta.Category != "数据库" || meta.AlwaysOn {
		t.Errorf("unexpected meta %+v", meta)
	}
	nav := m.Nav()
	if len(nav) != 1 || nav[0].Path != "/database" {
		t.Errorf("unexpected nav %+v", nav)
	}
	if err := m.HealthCheck(); err != nil {
		t.Errorf("HealthCheck should pass: %v", err)
	}
}

func TestNonAdminForbidden(t *testing.T) {
	for _, role := range []string{"readonly", "operator"} {
		audited := 0
		m, _, _ := newTestModule(t, role, &audited)
		r := router(m)
		cases := []struct {
			method, path, body string
		}{
			{"GET", "/mysql/databases", ""},
			{"POST", "/mysql/databases", `{"database":"d"}`},
			{"GET", "/settings", ""},
			{"PUT", "/settings", `{}`},
			{"GET", "/redis/info", ""},
		}
		for _, c := range cases {
			rec := do(r, c.method, c.path, c.body, nil)
			if rec.Code != http.StatusForbidden {
				t.Errorf("role %s %s %s = %d, want 403", role, c.method, c.path, rec.Code)
			}
		}
		if audited != 0 {
			t.Errorf("forbidden requests must not audit, got %d", audited)
		}
	}
}

func TestCreateDatabaseAdmin(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	rec := do(router(m), "POST", "/mysql/databases", `{"database":"my_app"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("create db = %d, body %s", rec.Code, rec.Body)
	}
	if len(sql.execs) != 1 || sql.execs[0] != "CREATE DATABASE `my_app`" {
		t.Errorf("exec = %v", sql.execs)
	}
	if audited != 1 {
		t.Errorf("create should audit once, got %d", audited)
	}
}

func TestCreateDatabasePG(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/postgres/databases", `{"database":"my_app"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("pg create db = %d", rec.Code)
	}
	if sql.execs[0] != `CREATE DATABASE "my_app"` {
		t.Errorf("pg exec = %v", sql.execs)
	}
}

func TestInjectionInDatabaseNameRejected(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	r := router(m)
	for _, name := range []string{"x; DROP DATABASE y", "a b", "back`tick", ""} {
		body := `{"database":"` + name + `"}`
		rec := do(r, "POST", "/mysql/databases", body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("name %q should be 400, got %d", name, rec.Code)
		}
	}
	if len(sql.execs) != 0 {
		t.Errorf("rejected injection must not reach SQL, got %v", sql.execs)
	}
	if audited != 0 {
		t.Errorf("rejected injection must not audit, got %d", audited)
	}
}

func TestInjectionInUserRejected(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/mysql/users", `{"user":"bad;user","password":"p"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad user should be 400, got %d", rec.Code)
	}
	if len(sql.execs) != 0 {
		t.Errorf("must not reach SQL, got %v", sql.execs)
	}
}

func TestDropDatabaseRequiresConfirm(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	r := router(m)
	// 无确认头 → 428
	rec := do(r, "DELETE", "/mysql/databases", `{"database":"d"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("drop without confirm = %d, want 428", rec.Code)
	}
	if len(sql.execs) != 0 || audited != 0 {
		t.Errorf("unconfirmed drop must not exec/audit")
	}
	// 带确认头 → 执行
	rec = do(r, "DELETE", "/mysql/databases", `{"database":"d"}`, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed drop = %d", rec.Code)
	}
	if sql.execs[0] != "DROP DATABASE `d`" {
		t.Errorf("drop exec = %v", sql.execs)
	}
	if audited != 1 {
		t.Errorf("confirmed drop should audit, got %d", audited)
	}
}

func TestDropUserRequiresConfirm(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	r := router(m)
	rec := do(r, "DELETE", "/postgres/users", `{"user":"u"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("drop user without confirm = %d, want 428", rec.Code)
	}
	rec = do(r, "DELETE", "/postgres/users", `{"user":"u"}`, map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusNoContent || sql.execs[0] != `DROP ROLE "u"` {
		t.Errorf("confirmed drop user code=%d execs=%v", rec.Code, sql.execs)
	}
}

func TestCreateUserPasswordNotInAudit(t *testing.T) {
	var auditDetail string
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 1, "admin" },
		Audit:     func(_ *int64, _, detail, _ string) { auditDetail = detail },
	}
	m := New("s", newTestStore(t), deps)
	sql := &mockSQL{}
	m.mysqlConn = func(context.Context, Settings) (sqlBackend, error) { return sql, nil }
	do(router(m), "POST", "/mysql/users", `{"user":"alice","password":"sup3rSecret"}`, nil)
	if strings.Contains(auditDetail, "sup3rSecret") {
		t.Errorf("audit detail leaks password: %q", auditDetail)
	}
	if sql.execs[0] != "CREATE USER `alice`@'%' IDENTIFIED BY 'sup3rSecret'" {
		t.Errorf("create user exec = %v", sql.execs)
	}
}

func TestGrantRevoke(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	r := router(m)
	do(r, "POST", "/mysql/grant", `{"database":"app","user":"alice"}`, nil)
	do(r, "POST", "/mysql/revoke", `{"database":"app","user":"alice"}`, nil)
	want := []string{
		"GRANT ALL PRIVILEGES ON `app`.* TO `alice`@'%'",
		"REVOKE ALL PRIVILEGES ON `app`.* FROM `alice`@'%'",
	}
	for i, w := range want {
		if i >= len(sql.execs) || sql.execs[i] != w {
			t.Errorf("exec[%d] = %v, want %q", i, sql.execs, w)
		}
	}
}

func TestListDatabases(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	sql.rows = []string{"information_schema", "app"}
	rec := do(router(m), "GET", "/mysql/databases", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "app") {
		t.Errorf("list body = %s", rec.Body)
	}
}

func TestRedisInfoDBSize(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	r := router(m)
	rec := do(r, "GET", "/redis/info", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "redis_version") {
		t.Errorf("redis info code=%d body=%s", rec.Code, rec.Body)
	}
	rec = do(r, "GET", "/redis/dbsize", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "42") {
		t.Errorf("redis dbsize code=%d body=%s", rec.Code, rec.Body)
	}
}

func TestRedisFlushRequiresConfirm(t *testing.T) {
	audited := 0
	m, _, redis := newTestModule(t, "admin", &audited)
	r := router(m)
	rec := do(r, "POST", "/redis/flushdb", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("flush without confirm = %d, want 428", rec.Code)
	}
	if redis.flushed {
		t.Error("unconfirmed flush must not flush")
	}
	rec = do(r, "POST", "/redis/flushdb", "", map[string]string{"X-Confirm-Danger": "x"})
	if rec.Code != http.StatusNoContent || !redis.flushed {
		t.Errorf("confirmed flush code=%d flushed=%v", rec.Code, redis.flushed)
	}
	if audited != 1 {
		t.Errorf("flush should audit once, got %d", audited)
	}
}

func TestSettingsGetMasksPassword(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	r := router(m)
	do(r, "PUT", "/settings", `{"mysql_password":"secret","mysql_port":3307}`, nil)
	rec := do(r, "GET", "/settings", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get settings = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret") {
		t.Errorf("GET /settings leaks password: %s", body)
	}
	if !strings.Contains(body, "3307") || !strings.Contains(body, "mysql") {
		t.Errorf("settings body missing fields: %s", body)
	}
}
