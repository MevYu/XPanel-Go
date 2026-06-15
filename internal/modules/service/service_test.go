package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func fakeDeps(role string, audited *int) Deps {
	return Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(userID *int64, action, detail, ip string) { *audited++ },
	}
}

func TestMetaSwitchable(t *testing.T) {
	m := New(fakeDeps("admin", new(int)))
	if m.Meta().ID != "service" || m.Meta().AlwaysOn {
		t.Errorf("service must be id=service, not AlwaysOn, got %+v", m.Meta())
	}
}

func TestRestartRequiresOperator(t *testing.T) {
	audited := 0
	m := New(fakeDeps("readonly", &audited))
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/restart", nil)
	req = req.WithContext(context.Background())
	r.ServeHTTP(rec, req.WithContext(req.Context()))
	// 缺 unit 参数也好、角色不足也好,readonly 必须被拒(403),且不触发审计成功路径
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusBadRequest {
		t.Fatalf("readonly restart should be 403/400, got %d", rec.Code)
	}
}

func TestRestartReadonlyForbiddenNoAudit(t *testing.T) {
	audited := 0
	m := New(fakeDeps("readonly", &audited))
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/restart?unit=nginx", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly restart with valid unit should be 403, got %d", rec.Code)
	}
	if audited != 0 {
		t.Fatalf("forbidden request must not be audited, got audited=%d", audited)
	}
}

func TestActionAuditsRegardlessOfOutcome(t *testing.T) {
	audited := 0
	m := New(fakeDeps("admin", &audited))
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/restart?unit=nginx", nil)
	r.ServeHTTP(rec, req)
	// ServiceAction may fail if systemctl is absent, but audit runs before the
	// error check, so audited must be 1 regardless of HTTP status.
	if audited != 1 {
		t.Fatalf("admin action must audit exactly once, got audited=%d (code=%d)", audited, rec.Code)
	}
}

func TestActionFailureMasksRawOutput(t *testing.T) {
	audited := 0
	m := New(fakeDeps("admin", &audited))
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/restart?unit=nginx", nil)
	r.ServeHTTP(rec, req)
	// In test env systemctl is typically absent, so ServiceAction fails with 500.
	if rec.Code != http.StatusInternalServerError {
		t.Skipf("expected systemctl-absent 500, got %d (systemctl present?)", rec.Code)
	}
	if got := rec.Body.String(); got != "service operation failed\n" {
		t.Errorf("failure body must be generic, got %q", got)
	}
}

func TestRestartRejectsBadUnit(t *testing.T) {
	audited := 0
	m := New(fakeDeps("admin", &audited))
	r := chi.NewRouter()
	m.Routes(r)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/restart?unit=nginx;rm", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad unit name should 400, got %d", rec.Code)
	}
}
