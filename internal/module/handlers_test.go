package module

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/go-chi/chi/v5"
)

// adminPrincipal 是测试用 principal stub,默认以 admin 身份放行变更接口。
func adminPrincipal(*http.Request) (int64, string) { return 1, "admin" }

func TestModulesListAndToggle(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := NewRegistry()
	reg.Register(routedModule{fakeModule{id: "svc", requires: nil}})
	mgr := NewManager(reg, st)

	root := chi.NewRouter()
	root.Mount("/api/modules", ModuleAPI(reg, mgr, adminPrincipal))

	// list:svc 存在且未启用
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("GET", "/api/modules", nil))
	if rec.Code != 200 {
		t.Fatalf("list status %d", rec.Code)
	}
	var list []struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].ID != "svc" || list[0].Enabled {
		t.Fatalf("unexpected list: %s", rec.Body.String())
	}

	// enable
	rec = httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("POST", "/api/modules/svc/enable", strings.NewReader("")))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("enable status %d (%s)", rec.Code, rec.Body.String())
	}
	if !mgr.IsEnabled("svc") {
		t.Error("svc should be enabled")
	}

	// enable 未知模块 → 404
	rec = httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("POST", "/api/modules/nope/enable", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown module enable should 404, got %d", rec.Code)
	}
}

func TestEnableRequiresAdmin(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := NewRegistry()
	reg.Register(routedModule{fakeModule{id: "svc"}})
	mgr := NewManager(reg, st)

	operator := func(*http.Request) (int64, string) { return 2, "operator" }
	root := chi.NewRouter()
	root.Mount("/api/modules", ModuleAPI(reg, mgr, operator))

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("POST", "/api/modules/svc/enable", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin enable should 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	if mgr.IsEnabled("svc") {
		t.Error("svc must not be enabled by non-admin")
	}
}

func TestModuleListNeverNullArrays(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := NewRegistry()
	// fakeModule 的 requires 为 nil、Nav() 返回 nil:确保序列化为 [] 而非 null。
	reg.Register(routedModule{fakeModule{id: "svc", requires: nil}})
	mgr := NewManager(reg, st)

	root := chi.NewRouter()
	root.Mount("/api/modules", ModuleAPI(reg, mgr, adminPrincipal))

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("GET", "/api/modules", nil))
	if rec.Code != 200 {
		t.Fatalf("list status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"requires":[]`) {
		t.Errorf("requires should be [], body: %q", body)
	}
	if strings.Contains(body, `"requires":null`) {
		t.Errorf("requires must not be null, body: %q", body)
	}
	if !strings.Contains(body, `"nav":[]`) {
		t.Errorf("nav should be [], body: %q", body)
	}
	if strings.Contains(body, `"nav":null`) {
		t.Errorf("nav must not be null, body: %q", body)
	}
}

// routedStartStop 把 startStopModule 暴露为带路由的 Module,供 ModuleAPI 挂载。
type routedStartStop struct{ *startStopModule }

func (routedStartStop) Routes(Router) {}

func TestDisableValidationErrorShown(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := NewRegistry()
	m := &startStopModule{fakeModule: fakeModule{id: "dash", alwaysOn: true}}
	reg.Register(routedStartStop{m})
	mgr := NewManager(reg, st)
	if err := mgr.Restore(); err != nil { // AlwaysOn 模块经 Restore 启用
		t.Fatalf("restore: %v", err)
	}
	if !mgr.IsEnabled("dash") {
		t.Fatal("dash should be enabled after restore")
	}

	root := chi.NewRouter()
	root.Mount("/api/modules", ModuleAPI(reg, mgr, adminPrincipal))

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("POST", "/api/modules/dash/disable", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("disable always-on should 409, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "always-on") {
		t.Errorf("validation error should be shown to user, body: %q", rec.Body.String())
	}
}

// routedStartFail 把 startFailModule 暴露为带路由的 Module。Start 失败仍是真错误,
// 用于验证内部错误信息不泄漏给客户端。
type routedStartFail struct{ startFailModule }

func (routedStartFail) Routes(Router) {}

func TestEnableInternalErrorMasked(t *testing.T) {
	// Start 失败是真正的内部错误,仍须屏蔽成通用文案(不泄漏内部路径)。
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := NewRegistry()
	reg.Register(routedStartFail{startFailModule{fakeModule: fakeModule{id: "svc"}}})
	mgr := NewManager(reg, st)

	root := chi.NewRouter()
	root.Mount("/api/modules", ModuleAPI(reg, mgr, adminPrincipal))

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("POST", "/api/modules/svc/enable", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("enable start failure should 409, got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "start boom") {
		t.Errorf("internal error leaked to client: %q", body)
	}
	if !strings.Contains(body, "module operation failed") {
		t.Errorf("expected generic message, got: %q", body)
	}
}

func TestModuleListIncludesHealth(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := NewRegistry()
	healthy := &startStopModule{fakeModule: fakeModule{id: "ok"}}
	degraded := &startStopModule{fakeModule: fakeModule{id: "bad"}, healthErr: errors.New("systemctl not found")}
	reg.Register(routedStartStop{healthy})
	reg.Register(routedStartStop{degraded})
	mgr := NewManager(reg, st)
	if err := mgr.Enable("ok"); err != nil {
		t.Fatalf("enable ok: %v", err)
	}
	if err := mgr.Enable("bad"); err != nil {
		t.Fatalf("enable bad (degraded) should succeed: %v", err)
	}

	root := chi.NewRouter()
	root.Mount("/api/modules", ModuleAPI(reg, mgr, adminPrincipal))

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("GET", "/api/modules", nil))
	if rec.Code != 200 {
		t.Fatalf("list status %d", rec.Code)
	}
	var list []struct {
		ID     string `json:"id"`
		Health struct {
			OK     bool   `json:"ok"`
			Reason string `json:"reason"`
		} `json:"health"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, rec.Body.String())
	}
	byID := map[string]struct {
		OK     bool
		Reason string
	}{}
	for _, it := range list {
		byID[it.ID] = struct {
			OK     bool
			Reason string
		}{it.Health.OK, it.Health.Reason}
	}
	if !byID["ok"].OK {
		t.Errorf("ok module health should be OK, got %+v", byID["ok"])
	}
	if byID["bad"].OK {
		t.Errorf("bad module health should not be OK, got %+v", byID["bad"])
	}
	if byID["bad"].Reason != "systemctl not found" {
		t.Errorf("bad module reason = %q, want %q", byID["bad"].Reason, "systemctl not found")
	}
	if !strings.Contains(rec.Body.String(), `"health"`) {
		t.Errorf("list item must contain health field, body: %s", rec.Body.String())
	}
}
