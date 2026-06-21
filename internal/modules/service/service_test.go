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

// actionModule 装配一个带样本服务列表 + stub action 的 admin 模块,便于测动作路径。
func actionModule(deps Deps, action func(verb, unit string) (string, error)) *Module {
	m := newWithRunner(deps, &fakeRunner{units: sampleListUnits, files: sampleListUnitFiles})
	m.action = action
	return m
}

// adminConfirm 构造带 admin 角色所需确认头的 POST 请求。
func adminConfirm(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("X-Confirm-Danger", "yes")
	return req
}

func TestActionAuditsRegardlessOfOutcome(t *testing.T) {
	audited := 0
	m := actionModule(fakeDeps("admin", &audited),
		func(string, string) (string, error) { return "", errBoom })
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, adminConfirm("POST", "/restart?unit=nginx.service"))
	// 动作失败,但审计在错误检查之前执行,故无论 HTTP 状态审计必为 1。
	if audited != 1 {
		t.Fatalf("admin action must audit exactly once, got audited=%d (code=%d)", audited, rec.Code)
	}
}

func TestActionFailureMasksRawOutput(t *testing.T) {
	audited := 0
	m := actionModule(fakeDeps("admin", &audited),
		func(string, string) (string, error) { return "secret internal detail", errBoom })
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, adminConfirm("POST", "/restart?unit=nginx.service"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("action error should 500, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != "service operation failed\n" {
		t.Errorf("failure body must be generic, got %q", got)
	}
}

func TestActionHappyPath(t *testing.T) {
	audited := 0
	var gotVerb, gotUnit string
	m := actionModule(fakeDeps("admin", &audited),
		func(verb, unit string) (string, error) { gotVerb, gotUnit = verb, unit; return "Done.", nil })
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, adminConfirm("POST", "/reload?unit=nginx.service"))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid admin+confirm+known-unit should 200, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	if gotVerb != "reload" || gotUnit != "nginx.service" {
		t.Errorf("action got verb=%q unit=%q", gotVerb, gotUnit)
	}
	if rec.Body.String() != "Done." {
		t.Errorf("body=%q, want passthrough output", rec.Body.String())
	}
	if audited != 1 {
		t.Errorf("success must audit once, got %d", audited)
	}
}

func TestActionNonAdminForbidden(t *testing.T) {
	audited := 0
	m := actionModule(fakeDeps("operator", &audited),
		func(string, string) (string, error) { t.Fatal("action must not run"); return "", nil })
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, adminConfirm("POST", "/restart?unit=nginx.service"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator must be 403, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("forbidden must not audit, got %d", audited)
	}
}

func TestActionMissingConfirmHeader(t *testing.T) {
	audited := 0
	m := actionModule(fakeDeps("admin", &audited),
		func(string, string) (string, error) { t.Fatal("action must not run"); return "", nil })
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/restart?unit=nginx.service", nil) // 无确认头
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing X-Confirm-Danger must be 428, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("rejected request must not audit, got %d", audited)
	}
}

func TestActionUnitNotInWhitelist(t *testing.T) {
	audited := 0
	m := actionModule(fakeDeps("admin", &audited),
		func(string, string) (string, error) { t.Fatal("action must not run"); return "", nil })
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	// 合法 unit 名但不在样本服务列表中。
	r.ServeHTTP(rec, adminConfirm("POST", "/restart?unit=notreal.service"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unit not in list must be 400, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("rejected request must not audit, got %d", audited)
	}
}

func TestRestartRejectsBadUnit(t *testing.T) {
	audited := 0
	m := actionModule(fakeDeps("admin", &audited),
		func(string, string) (string, error) { t.Fatal("action must not run"); return "", nil })
	r := chi.NewRouter()
	m.Routes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, adminConfirm("POST", "/restart?unit=nginx;rm"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad unit name should 400, got %d", rec.Code)
	}
}
