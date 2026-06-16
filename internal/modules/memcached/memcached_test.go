package memcached

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockClient 是 Client 的测试替身,记录调用并返回预置数据。
type mockClient struct {
	stats    map[string]string
	statsErr error
	flushed  int
	flushErr error
}

func (c *mockClient) Stats(string) (map[string]string, error) { return c.stats, c.statsErr }
func (c *mockClient) Slabs(string) (map[string]map[string]string, error) {
	return groupSlabs(c.stats), c.statsErr
}
func (c *mockClient) FlushAll(string) error {
	c.flushed++
	return c.flushErr
}

func newTestModule(t *testing.T, role string, client Client, audited *int) (*Module, chi.Router) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	}
	m := New(st, client, deps)
	r := chi.NewRouter()
	m.Routes(r)
	return m, r
}

func TestMetaSwitchable(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockClient{}, new(int))
	meta := m.Meta()
	if meta.ID != "memcached" || meta.Category != "数据库" || meta.AlwaysOn {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	if nav := m.Nav(); len(nav) != 1 || nav[0].Icon != "zap" || nav[0].Path != "/memcached" {
		t.Fatalf("unexpected nav: %+v", nav)
	}
}

func TestStatsReadable(t *testing.T) {
	cl := &mockClient{stats: map[string]string{"get_hits": "9", "get_misses": "1", "version": "1.6"}}
	_, r := newTestModule(t, "readonly", cl, new(int))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("stats should be 200 for readonly, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"hit_rate":0.9`) {
		t.Errorf("body missing hit_rate: %s", rec.Body.String())
	}
}

func TestStatsConnErrorIsBadGateway(t *testing.T) {
	cl := &mockClient{statsErr: errTest}
	_, r := newTestModule(t, "admin", cl, new(int))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/stats", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("conn error should be 502, got %d", rec.Code)
	}
}

func TestPutSettingsRequiresAdmin(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "operator", &mockClient{}, &audited)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/settings", strings.NewReader(`{"addr":"127.0.0.1:11211","service_unit":"memcached"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator PUT settings should be 403, got %d", rec.Code)
	}
	if audited != 0 {
		t.Fatalf("forbidden must not audit, got %d", audited)
	}
}

func TestPutSettingsValidatesAddr(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &mockClient{}, &audited)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/settings", strings.NewReader(`{"addr":"nohostport","service_unit":"memcached"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid addr should be 400, got %d", rec.Code)
	}
	if audited != 0 {
		t.Fatalf("rejected settings must not audit, got %d", audited)
	}
}

func TestPutSettingsPersists(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &mockClient{}, &audited)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/settings", strings.NewReader(`{"addr":"10.0.0.5:11212","service_unit":"memcached"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid settings should be 200, got %d", rec.Code)
	}
	if audited != 1 {
		t.Fatalf("settings update must audit once, got %d", audited)
	}
	s, _ := m.ms.getSettings()
	if s.Addr != "10.0.0.5:11212" {
		t.Fatalf("settings not persisted, got %+v", s)
	}
}

func TestFlushRequiresAdmin(t *testing.T) {
	cl := &mockClient{}
	audited := 0
	_, r := newTestModule(t, "operator", cl, &audited)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/flush", nil)
	req.Header.Set("X-Confirm-Danger", "yes")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator flush should be 403, got %d", rec.Code)
	}
	if cl.flushed != 0 || audited != 0 {
		t.Fatalf("forbidden flush must not run or audit")
	}
}

func TestFlushRequiresConfirmHeader(t *testing.T) {
	cl := &mockClient{}
	audited := 0
	_, r := newTestModule(t, "admin", cl, &audited)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/flush", nil))
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("flush without confirm should be 428, got %d", rec.Code)
	}
	if cl.flushed != 0 || audited != 0 {
		t.Fatalf("unconfirmed flush must not run or audit")
	}
}

func TestFlushSucceedsWithAdminAndConfirm(t *testing.T) {
	cl := &mockClient{}
	audited := 0
	_, r := newTestModule(t, "admin", cl, &audited)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/flush", nil)
	req.Header.Set("X-Confirm-Danger", "yes")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed admin flush should be 200, got %d", rec.Code)
	}
	if cl.flushed != 1 {
		t.Fatalf("flush_all must run once, got %d", cl.flushed)
	}
	if audited != 1 {
		t.Fatalf("flush must audit once, got %d", audited)
	}
}

func TestActionRequiresAdmin(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "operator", &mockClient{}, &audited)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/restart", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator restart should be 403, got %d", rec.Code)
	}
	if audited != 0 {
		t.Fatalf("forbidden restart must not audit, got %d", audited)
	}
}

func TestHealthCheckUsesClient(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockClient{statsErr: errTest}, new(int))
	if m.HealthCheck() == nil {
		t.Fatal("HealthCheck should fail when client can't reach memcached")
	}
	m2, _ := newTestModule(t, "admin", &mockClient{stats: map[string]string{}}, new(int))
	if err := m2.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck should pass when reachable, got %v", err)
	}
}

type testErr struct{}

func (testErr) Error() string { return "test error" }

var errTest = testErr{}
