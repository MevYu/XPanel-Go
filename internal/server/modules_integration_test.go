package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/modules/dashboard"
	"github.com/MevYu/XPanel-Go/internal/store"
)

func TestDashboardMountedAndAlwaysOn(t *testing.T) {
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	svc := auth.NewService(st, jm, auth.NewLockout(5, time.Minute, time.Now))

	reg := module.NewRegistry()
	reg.Register(dashboard.New())
	mgr := module.NewManager(reg, st)
	if err := mgr.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	h := NewWithModules(svc, jm, reg, mgr)

	// 模块路由在 RequireAuth 组内,需带 Bearer token。
	token, err := jm.Issue(1, "admin")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// dashboard 是 AlwaysOn,恢复后 /api/m/dashboard/metrics 应可达(200)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/m/dashboard/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("dashboard metrics should be 200, got %d", rec.Code)
	}
}
