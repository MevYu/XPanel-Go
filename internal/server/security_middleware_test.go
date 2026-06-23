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
	"github.com/MevYu/XPanel-Go/internal/store"
)

func TestIPBanMiddlewareRejectsBannedIP(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := IPBanMiddleware(func(ip string) bool { return ip == "1.2.3.4" }, remoteIP)(ok)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/anything", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("banned ip should be rejected, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/anything", nil)
	req.RemoteAddr = "9.9.9.9:5555"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unbanned ip should pass, got %d", rec.Code)
	}
}

func TestEntryGate(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	const entry = "/abc123def456"
	h := EntryGate(entry, nil, nil, nil)(ok)

	pass := []string{
		entry, entry + "/", entry + "/dashboard",
		"/api/modules", "/api/auth/login", "/s/token", "/healthz",
		"/assets/index.js",
	}
	for _, p := range pass {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s should pass entry gate, got %d", p, rec.Code)
		}
	}

	block := []string{"/", "/login", "/random", "/dashboard", "/abc"}
	for _, p := range block {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s should be 404 (hidden), got %d", p, rec.Code)
		}
	}
}

// 端到端:3 次登录失败后,该 IP 对任意端点(含 /healthz)都被封禁中间件拒绝。
func TestLoginFailuresBanIPAcrossAllEndpoints(t *testing.T) {
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	guard, err := auth.NewIPBanGuard(st, 3, 72*time.Hour, time.Now)
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	svc := auth.NewService(st, jm, auth.NewLockout(5, time.Minute, time.Now)).WithIPBan(guard)
	if err := svc.Register("admin", "correct-horse", "admin"); err != nil {
		t.Fatalf("register: %v", err)
	}

	reg := module.NewRegistry()
	reg.Register(dashboard.New(st, dashboard.Deps{Principal: PrincipalFromRequest}))
	mgr := module.NewManager(reg, st)
	if err := mgr.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	h := NewWithModules(svc, jm, reg, mgr, nil, guard.Banned, nil, "/", nil, []byte("test-secret-32-bytes-long-xxxxxx"), nil, nil, nil, nil, nil)

	login := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.RemoteAddr = "7.7.7.7:1111"
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 3; i++ {
		login()
	}

	// 同 IP 访问 /healthz(本不需认证)现应被封禁中间件拒绝。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	req.RemoteAddr = "7.7.7.7:2222"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("banned IP should be blocked on /healthz, got %d", rec.Code)
	}

	// 不同 IP 不受影响。
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/healthz", nil)
	req.RemoteAddr = "8.8.8.8:2222"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("other IP should not be banned, got %d", rec.Code)
	}
}

// 端到端:同一 IP 扫描隐藏入口(错误路径 404)超阈值后,该 IP 被封禁,后续任意请求被拒。
func TestEntryProbeBansScannerAcrossAllEndpoints(t *testing.T) {
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	guard, err := auth.NewIPBanGuard(st, 3, 72*time.Hour, time.Now)
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	svc := auth.NewService(st, jm, auth.NewLockout(5, time.Minute, time.Now)).WithIPBan(guard)

	reg := module.NewRegistry()
	reg.Register(dashboard.New(st, dashboard.Deps{Principal: PrincipalFromRequest}))
	mgr := module.NewManager(reg, st)
	if err := mgr.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}

	const entry = "/abc123def456"
	probe := NewEntryProbeGuard(3, time.Hour, guard.Ban, time.Now)
	h := NewWithModules(svc, jm, reg, mgr, nil, guard.Banned, nil, entry, probe, []byte("test-secret-32-bytes-long-xxxxxx"), nil, nil, nil, nil, nil)

	scanner := "6.6.6.6"
	hit := func(path string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = scanner + ":1111"
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// 前 3 次扫描错误路径:404(探测命中,未超阈值,未封)。
	for i, p := range []string{"/wp-admin", "/login", "/admin"} {
		if got := hit(p); got != http.StatusNotFound {
			t.Fatalf("scan #%d %s want 404, got %d", i, p, got)
		}
	}
	// 第 4 次 > max=3:触发封禁。该次请求由 EntryGate 仍返回 404。
	if got := hit("/phpmyadmin"); got != http.StatusNotFound {
		t.Fatalf("4th scan want 404, got %d", got)
	}
	// 被封后:任意请求(含 /healthz)被 IPBanMiddleware 拒。
	if got := hit("/healthz"); got != http.StatusTooManyRequests {
		t.Fatalf("scanner should be banned, got %d", got)
	}

	// 正常用户:正确入口 / /healthz / /api 不计探测、不被封。
	other := "4.4.4.4"
	hitOther := func(path string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = other + ":2222"
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 10; i++ {
		hitOther(entry)
		hitOther("/healthz")
		hitOther("/api/modules")
	}
	if got := hitOther("/healthz"); got == http.StatusTooManyRequests {
		t.Fatal("legit traffic must not trigger probe ban")
	}
}
