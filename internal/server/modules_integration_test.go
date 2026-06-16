package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/modules/dashboard"
	"github.com/MevYu/XPanel-Go/internal/modules/files"
	"github.com/MevYu/XPanel-Go/internal/modules/terminal"
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

	h := NewWithModules(svc, jm, reg, mgr, nil, nil, "/")

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

// publicTestEnv 装配 dashboard(AlwaysOn 回归)+ files + terminal,后两者实现 PublicRouter。
func publicTestEnv(t *testing.T) http.Handler {
	t.Helper()
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	svc := auth.NewService(st, jm, auth.NewLockout(5, time.Minute, time.Now))

	noopAudit := func(*int64, string, string, string) {}
	reg := module.NewRegistry()
	reg.Register(dashboard.New())
	fm, err := files.New(t.TempDir(), st, files.Deps{Principal: PrincipalFromRequest, Audit: noopAudit})
	if err != nil {
		t.Fatalf("files.New: %v", err)
	}
	reg.Register(fm)
	reg.Register(terminal.New(terminal.Deps{Principal: PrincipalFromRequest, Audit: noopAudit}))

	mgr := module.NewManager(reg, st)
	if err := mgr.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	// 默认只有 dashboard(AlwaysOn)启用;按需在用例里 Enable files/terminal。
	if err := mgr.Enable("files"); err != nil {
		t.Fatalf("enable files: %v", err)
	}
	if err := mgr.Enable("terminal"); err != nil {
		t.Fatalf("enable terminal: %v", err)
	}
	return NewWithModules(svc, jm, reg, mgr, nil, nil, "/")
}

// 文件外链在无 Authorization 头下应到达模块 handler(404,不存在的 token),而非被 RequireAuth 拦成 401。
func TestPublicFileShareReachableWithoutAuth(t *testing.T) {
	h := publicTestEnv(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/s/nonexistent-token", nil)
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("public share must not be gated by RequireAuth, got 401")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown share token should be 404, got %d", rec.Code)
	}
}

// terminal WS 在无 ticket、无 Authorization 头下应到达 handler 并被 ticket 校验拒绝(401),
// 而非被 RequireAuth 拦截。两者都是 401,用 body 文案区分鉴权来源。
func TestPublicTerminalWSReachesTicketCheck(t *testing.T) {
	h := publicTestEnv(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/m/terminal/ws", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("WS without ticket should be 401 from ticket check, got %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "ticket") {
		t.Fatalf("401 should come from ticket check (body=%q), not RequireAuth", body)
	}
}

// 模块停用后,公开路由经 enable-gate 返回 404。
func TestPublicRouteGatedWhenDisabled(t *testing.T) {
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	svc := auth.NewService(st, jm, auth.NewLockout(5, time.Minute, time.Now))

	noopAudit := func(*int64, string, string, string) {}
	reg := module.NewRegistry()
	reg.Register(dashboard.New())
	reg.Register(terminal.New(terminal.Deps{Principal: PrincipalFromRequest, Audit: noopAudit}))
	mgr := module.NewManager(reg, st)
	if err := mgr.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	// terminal 未启用:公开 WS 路由应被 enable-gate 成 404。
	h := NewWithModules(svc, jm, reg, mgr, nil, nil, "/")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/m/terminal/ws?ticket=x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled module public route should be 404, got %d", rec.Code)
	}
}
