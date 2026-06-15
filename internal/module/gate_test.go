package module

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/go-chi/chi/v5"
)

type routedModule struct{ fakeModule }

func (routedModule) Routes(r Router) {
	r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("pong")) })
}

func TestGateBlocksDisabledModule(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	reg := NewRegistry()
	reg.Register(routedModule{fakeModule{id: "svc"}})
	mgr := NewManager(reg, st)

	root := chi.NewRouter()
	Mount(root, reg, mgr)

	// 未启用:404
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("GET", "/api/m/svc/ping", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled module should 404, got %d", rec.Code)
	}

	// 启用后:200 pong
	mgr.Enable("svc")
	rec = httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("GET", "/api/m/svc/ping", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "pong" {
		t.Errorf("enabled module should serve, got %d %q", rec.Code, rec.Body.String())
	}
}
