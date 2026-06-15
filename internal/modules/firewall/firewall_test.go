package firewall

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func fakeDeps(role string, audited *int) Deps {
	return Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(userID *int64, action, detail, ip string) { *audited++ },
	}
}

func newRouter(role string, audited *int) chi.Router {
	m := New(fakeDeps(role, audited))
	r := chi.NewRouter()
	m.Routes(r)
	return r
}

func TestMetaSwitchable(t *testing.T) {
	m := New(fakeDeps("admin", new(int)))
	meta := m.Meta()
	if meta.ID != "firewall" || meta.AlwaysOn {
		t.Errorf("firewall must be id=firewall, not AlwaysOn, got %+v", meta)
	}
	if meta.Category != "安全" {
		t.Errorf("category must be 安全, got %q", meta.Category)
	}
}

func TestNav(t *testing.T) {
	nav := New(fakeDeps("admin", new(int))).Nav()
	if len(nav) != 1 || nav[0].Path != "/firewall" {
		t.Errorf("nav must expose /firewall, got %+v", nav)
	}
}

func TestRuleChangeRequiresAdmin(t *testing.T) {
	for _, role := range []string{"readonly", "operator"} {
		audited := 0
		r := newRouter(role, &audited)
		rec := httptest.NewRecorder()
		body := `{"action":"allow","port":80,"proto":"tcp"}`
		req := httptest.NewRequest("POST", "/rules", strings.NewReader(body))
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("role %s rule change should be 403, got %d", role, rec.Code)
		}
		if audited != 0 {
			t.Errorf("role %s forbidden request must not audit, got %d", role, audited)
		}
	}
}

func TestRuleChangeRejectsInvalidPort(t *testing.T) {
	audited := 0
	r := newRouter("admin", &audited)
	rec := httptest.NewRecorder()
	body := `{"action":"allow","port":0,"proto":"tcp"}`
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(body))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid port must 400 before exec, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("rejected-before-exec request must not audit, got %d", audited)
	}
}

func TestRuleChangeRejectsInjectionSource(t *testing.T) {
	audited := 0
	r := newRouter("admin", &audited)
	rec := httptest.NewRecorder()
	body := `{"action":"allow","port":80,"proto":"tcp","source":"1.2.3.4; rm -rf /"}`
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(body))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("injection source must 400, got %d", rec.Code)
	}
}

func TestRuleChangeRejectsBadProto(t *testing.T) {
	audited := 0
	r := newRouter("admin", &audited)
	rec := httptest.NewRecorder()
	body := `{"action":"allow","port":80,"proto":"icmp"}`
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(body))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad proto must 400, got %d", rec.Code)
	}
}

func TestDeleteRuleRequiresConfirm(t *testing.T) {
	audited := 0
	r := newRouter("admin", &audited)
	rec := httptest.NewRecorder()
	body := `{"action":"allow","port":80,"proto":"tcp"}`
	// no confirm header -> dangerous op must be refused with 428.
	req := httptest.NewRequest("DELETE", "/rules", strings.NewReader(body))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("delete without confirm must be 428, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("unconfirmed delete must not audit, got %d", audited)
	}
}

func TestDisableRequiresConfirm(t *testing.T) {
	audited := 0
	r := newRouter("admin", &audited)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/disable", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("disable without confirm must be 428, got %d", rec.Code)
	}
}

func TestDisableRequiresAdmin(t *testing.T) {
	audited := 0
	r := newRouter("operator", &audited)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/disable", nil)
	req.Header.Set("X-Confirm-Danger", "yes")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator disable must be 403, got %d", rec.Code)
	}
}

func TestListIsReadable(t *testing.T) {
	// List requires auth but not admin; readonly should pass RBAC. It may then
	// 500 if no backend is present, which is fine — we only assert it's not 403.
	audited := 0
	r := newRouter("readonly", &audited)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/rules", nil)
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Errorf("list must not require admin, got 403")
	}
}
