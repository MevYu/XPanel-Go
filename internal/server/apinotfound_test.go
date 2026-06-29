package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/modules/dashboard"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// apiNotFoundEnv 装配生产路由(NewWithModules)+ dashboard(AlwaysOn),entryPath="/"。
func apiNotFoundEnv(t *testing.T) (http.Handler, string) {
	t.Helper()
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	svc := auth.NewService(st, jm, auth.NewLockout(5, time.Minute, time.Now))

	reg := module.NewRegistry()
	reg.Register(dashboard.New(st, dashboard.Deps{Principal: PrincipalFromRequest}))
	mgr := module.NewManager(reg, st)
	if err := mgr.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	h := NewWithModules(svc, jm, reg, mgr, nil, nil, nil, "/", nil, []byte("test-secret-32-bytes-long-xxxxxx"), nil, nil, nil, nil, nil)

	token, err := jm.Issue(1, "admin")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return h, token
}

// 未注册的 /api/* 必须返回 404 + JSON 错误体,而非 SPA 的 200 HTML,
// 否则前端 apiFetch 会对 HTML 做 JSON.parse 直接崩。
func TestUnregisteredAPIPathReturns404JSON(t *testing.T) {
	h, _ := apiNotFoundEnv(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/does-not-exist", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("unregistered /api path should be 404, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type should be application/json, got %q", ct)
	}
	body := rec.Body.String()
	if strings.Contains(body, "__XPANEL_BASE__") || strings.Contains(body, "<!DOCTYPE") {
		t.Fatalf("404 body must be JSON, not SPA HTML: %q", body)
	}
	var v map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("404 body must be valid JSON: %v (body=%q)", err, body)
	}
}

// 回归保护:非 API 路径(SPA 入口与客户端路由)仍返回 200 的 index.html。
func TestSPAFallbackUnaffected(t *testing.T) {
	h, _ := apiNotFoundEnv(t)

	for _, path := range []string{"/", "/dashboard"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("SPA path %q should be 200, got %d", path, rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, "__XPANEL_BASE__") {
			t.Fatalf("SPA path %q should serve index.html (base marker), got %q", path, body)
		}
	}
}

// 已注册端点不受 catch-all 影响:公开健康检查、需鉴权的 /api/ 路由仍走各自 handler。
func TestRegisteredEndpointsUnaffected(t *testing.T) {
	h, token := apiNotFoundEnv(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("/healthz should be 200 ok, got %d %q", rec.Code, rec.Body.String())
	}

	// 已注册的 /api/ 路由仍路由到 handler:无 token 时由 RequireAuth 返回 401(而非被 catch-all 404)。
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/modules", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("registered /api/modules without token should be 401 (RequireAuth), got %d", rec.Code)
	}

	// 带 token 的已注册模块路由仍 200。
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/m/dashboard/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("registered /api/m/dashboard/metrics with token should be 200, got %d", rec.Code)
	}
}
