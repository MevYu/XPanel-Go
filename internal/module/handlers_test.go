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

func TestModulesListAndToggle(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := NewRegistry()
	reg.Register(routedModule{fakeModule{id: "svc", requires: nil}})
	mgr := NewManager(reg, st)

	root := chi.NewRouter()
	root.Mount("/api/modules", ModuleAPI(reg, mgr))

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
	root.Mount("/api/modules", ModuleAPI(reg, mgr))

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("POST", "/api/modules/dash/disable", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("disable always-on should 409, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "always-on") {
		t.Errorf("validation error should be shown to user, body: %q", rec.Body.String())
	}
}

func TestEnableInternalErrorMasked(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := NewRegistry()
	m := &startStopModule{fakeModule: fakeModule{id: "svc"}, healthErr: errors.New("/secret/path missing")}
	reg.Register(routedStartStop{m})
	mgr := NewManager(reg, st)

	root := chi.NewRouter()
	root.Mount("/api/modules", ModuleAPI(reg, mgr))

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("POST", "/api/modules/svc/enable", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("enable health-check failure should 409, got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "/secret/path") {
		t.Errorf("internal error leaked to client: %q", body)
	}
	if !strings.Contains(body, "module operation failed") {
		t.Errorf("expected generic message, got: %q", body)
	}
}
