package module

import (
	"encoding/json"
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
