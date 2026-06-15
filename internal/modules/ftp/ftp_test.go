package ftp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockBackend 记录调用,断言口令不落库且参数正确。available 可控以测 HealthCheck。
type mockBackend struct {
	created   []account // 记录创建(含口令,用于断言"口令到了后端而非 DB")
	createdPw []string
	deleted   []string
	passwords map[string]string
	toggled   map[string]bool
	avail     error
	failNext  bool // 令下一次写操作返回错误
}

func newMockBackend() *mockBackend {
	return &mockBackend{passwords: map[string]string{}, toggled: map[string]bool{}}
}

func (m *mockBackend) list(context.Context) ([]account, error) {
	return []account{{User: "alice", Home: "/home/ftp/alice"}}, nil
}
func (m *mockBackend) create(_ context.Context, user, password, home string, _ bool) error {
	if m.failNext {
		m.failNext = false
		return context.DeadlineExceeded
	}
	m.created = append(m.created, account{User: user, Home: home})
	m.createdPw = append(m.createdPw, password)
	return nil
}
func (m *mockBackend) delete(_ context.Context, user string) error {
	m.deleted = append(m.deleted, user)
	return nil
}
func (m *mockBackend) setPassword(_ context.Context, user, password string) error {
	m.passwords[user] = password
	return nil
}
func (m *mockBackend) setEnabled(_ context.Context, user string, enabled bool) error {
	m.toggled[user] = enabled
	return nil
}
func (m *mockBackend) available() error { return m.avail }

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

type auditRec struct {
	count   int
	details []string
}

func newTestModule(t *testing.T, role string, be *mockBackend, ar *auditRec) *Module {
	t.Helper()
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 7, role },
		Audit: func(_ *int64, _, detail, _ string) {
			ar.count++
			ar.details = append(ar.details, detail)
		},
	}
	return New(newTestStore(t), be, deps)
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

func TestMetaSwitchable(t *testing.T) {
	m := newTestModule(t, "admin", newMockBackend(), &auditRec{})
	if m.Meta().ID != "ftp" || m.Meta().AlwaysOn {
		t.Errorf("ftp must be id=ftp, not AlwaysOn, got %+v", m.Meta())
	}
	if m.Meta().Category != "网站" {
		t.Errorf("category should be 网站, got %q", m.Meta().Category)
	}
}

func TestNonAdminForbidden(t *testing.T) {
	ar := &auditRec{}
	m := newTestModule(t, "operator", newMockBackend(), ar)
	r := router(m)
	cases := []struct{ method, path, body string }{
		{"GET", "/accounts", ""},
		{"POST", "/accounts", `{"user":"bob","password":"x"}`},
		{"DELETE", "/accounts/bob", ""},
		{"POST", "/accounts/bob/password", `{"password":"x"}`},
		{"POST", "/accounts/bob/enable", ""},
		{"GET", "/settings", ""},
		{"PUT", "/settings", `{}`},
	}
	for _, c := range cases {
		rec := do(r, c.method, c.path, c.body, map[string]string{"X-Confirm-Danger": "1"})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403", c.method, c.path, rec.Code)
		}
	}
	if ar.count != 0 {
		t.Errorf("forbidden requests must not audit, got %d", ar.count)
	}
}

func TestCreatePasswordNeverPersisted(t *testing.T) {
	be := newMockBackend()
	ar := &auditRec{}
	m := newTestModule(t, "admin", be, ar)
	r := router(m)
	const secret = "SuperSecret123!"
	rec := do(r, "POST", "/accounts", `{"user":"bob","password":"`+secret+`","home":"/home/ftp/bob"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("create got %d body=%q", rec.Code, rec.Body.String())
	}
	// 口令到了后端 mock。
	if len(be.createdPw) != 1 || be.createdPw[0] != secret {
		t.Fatalf("backend should receive password, got %v", be.createdPw)
	}
	// 口令绝不落 XPanel 的库:扫描整张 ftp_accounts 不含明文。
	rows, err := m.ss.db.Query(`SELECT user, home, readonly, enabled FROM ftp_accounts`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var u, h string
		var ro, en int
		if err := rows.Scan(&u, &h, &ro, &en); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(u+h, secret) {
			t.Fatal("password leaked into ftp_accounts metadata")
		}
	}
	// 审计 detail 不含口令。
	for _, d := range ar.details {
		if strings.Contains(d, secret) {
			t.Fatalf("audit detail leaked password: %q", d)
		}
	}
}

func TestCreateRejectsBadUserAndPath(t *testing.T) {
	be := newMockBackend()
	m := newTestModule(t, "admin", be, &auditRec{})
	r := router(m)
	// 注入用户名
	rec := do(r, "POST", "/accounts", `{"user":"a;rm -rf /","password":"x"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("injection user should 400, got %d", rec.Code)
	}
	// 家目录逃逸
	rec = do(r, "POST", "/accounts", `{"user":"bob","password":"x","home":"/etc/passwd"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("escaping home should 400, got %d", rec.Code)
	}
	// 口令含换行
	rec = do(r, "POST", "/accounts", "{\"user\":\"bob\",\"password\":\"a\\nb\"}", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("password with newline should 400, got %d", rec.Code)
	}
	if len(be.created) != 0 {
		t.Errorf("no account should be created on validation failure, got %d", len(be.created))
	}
}

func TestDeleteRequiresConfirmAndAudits(t *testing.T) {
	be := newMockBackend()
	ar := &auditRec{}
	m := newTestModule(t, "admin", be, ar)
	r := router(m)
	// 缺确认头
	rec := do(r, "DELETE", "/accounts/bob", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	if ar.count != 0 || len(be.deleted) != 0 {
		t.Fatal("unconfirmed delete must not act or audit")
	}
	// 带确认头
	rec = do(r, "DELETE", "/accounts/bob", "", map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed delete got %d", rec.Code)
	}
	if len(be.deleted) != 1 || be.deleted[0] != "bob" {
		t.Fatalf("backend delete not called, got %v", be.deleted)
	}
	if ar.count != 1 {
		t.Fatalf("delete should audit once, got %d", ar.count)
	}
}

func TestDeleteRejectsBadUser(t *testing.T) {
	m := newTestModule(t, "admin", newMockBackend(), &auditRec{})
	r := router(m)
	rec := do(r, "DELETE", "/accounts/a%20b", "", map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad user delete should 400, got %d", rec.Code)
	}
}

func TestPasswordChangeNotInAudit(t *testing.T) {
	be := newMockBackend()
	ar := &auditRec{}
	m := newTestModule(t, "admin", be, ar)
	r := router(m)
	const secret = "N3wPass!"
	rec := do(r, "POST", "/accounts/alice/password", `{"password":"`+secret+`"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("password change got %d", rec.Code)
	}
	if be.passwords["alice"] != secret {
		t.Fatalf("backend should receive new password")
	}
	for _, d := range ar.details {
		if strings.Contains(d, secret) {
			t.Fatalf("audit detail leaked password: %q", d)
		}
	}
}

func TestToggleEnableDisable(t *testing.T) {
	be := newMockBackend()
	m := newTestModule(t, "admin", be, &auditRec{})
	r := router(m)
	if rec := do(r, "POST", "/accounts/alice/disable", "", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("disable got %d", rec.Code)
	}
	if be.toggled["alice"] {
		t.Error("alice should be disabled")
	}
	if rec := do(r, "POST", "/accounts/alice/enable", "", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("enable got %d", rec.Code)
	}
	if !be.toggled["alice"] {
		t.Error("alice should be enabled")
	}
}

func TestSettingsRoundTripAndDefaults(t *testing.T) {
	m := newTestModule(t, "admin", newMockBackend(), &auditRec{})
	r := router(m)
	// 默认值
	rec := do(r, "GET", "/settings", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/home/ftp") {
		t.Fatalf("default home_base missing: %d %s", rec.Code, rec.Body.String())
	}
	// 改路径
	rec = do(r, "PUT", "/settings", `{"home_base":"/srv/ftp","config_dir":"/etc/vsftpd"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put settings got %d", rec.Code)
	}
	eff, err := m.ss.effective()
	if err != nil || eff.HomeBase != "/srv/ftp" || eff.ConfigDir != "/etc/vsftpd" {
		t.Fatalf("settings not persisted: %+v %v", eff, err)
	}
	// 相对路径拒绝
	rec = do(r, "PUT", "/settings", `{"home_base":"relative"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("relative home_base should 400, got %d", rec.Code)
	}
}

func TestNewAccountHomeUsesUpdatedBase(t *testing.T) {
	be := newMockBackend()
	m := newTestModule(t, "admin", be, &auditRec{})
	r := router(m)
	do(r, "PUT", "/settings", `{"home_base":"/srv/ftp"}`, nil)
	rec := do(r, "POST", "/accounts", `{"user":"carol","password":"pw1234"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("create got %d", rec.Code)
	}
	if len(be.created) != 1 || be.created[0].Home != "/srv/ftp/carol" {
		t.Fatalf("home should default to base/user, got %v", be.created)
	}
}

func TestHealthCheckReflectsBackend(t *testing.T) {
	be := newMockBackend()
	m := newTestModule(t, "admin", be, &auditRec{})
	if err := m.HealthCheck(); err != nil {
		t.Errorf("available backend should pass health, got %v", err)
	}
	be.avail = context.Canceled
	if m.HealthCheck() == nil {
		t.Error("unavailable backend should fail health")
	}
}

func TestCreateBackendFailureStillAuditsNoMeta(t *testing.T) {
	be := newMockBackend()
	be.failNext = true
	ar := &auditRec{}
	m := newTestModule(t, "admin", be, ar)
	r := router(m)
	rec := do(r, "POST", "/accounts", `{"user":"dave","password":"pw1234"}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("backend failure should 502, got %d", rec.Code)
	}
	if ar.count != 1 {
		t.Fatalf("failed create should still audit once, got %d", ar.count)
	}
	// 后端失败时不应落账户元数据。
	metas, _ := m.ss.listAccounts()
	if len(metas) != 0 {
		t.Fatalf("failed create must not persist meta, got %d", len(metas))
	}
}
