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

var cookieSecret = []byte("test-secret-32-bytes-long-xxxxxx")

// 有效 cookie:种入后能验回同一 uid。
func TestLoginCookieRoundTrip(t *testing.T) {
	lc := newLoginCookie(cookieSecret)
	rec := httptest.NewRecorder()
	lc.set(rec, httptest.NewRequest("GET", "/", nil), 42)

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	uid, ok := lc.verify(req)
	if !ok || uid != 42 {
		t.Fatalf("want uid=42 ok=true, got uid=%d ok=%v", uid, ok)
	}
}

// 伪造/篡改签名 → 当作未登录。
func TestLoginCookieRejectsTampered(t *testing.T) {
	lc := newLoginCookie(cookieSecret)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: loginCookieName, Value: "bogus-not-a-real-signature"})
	if _, ok := lc.verify(req); ok {
		t.Fatal("tampered cookie must not verify")
	}

	// 用不同密钥签名的 cookie 也无效。
	other := newLoginCookie([]byte("different-secret-32-bytes-xxxxxx"))
	rec := httptest.NewRecorder()
	other.set(rec, httptest.NewRequest("GET", "/", nil), 7)
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		req2.AddCookie(c)
	}
	if _, ok := lc.verify(req2); ok {
		t.Fatal("cookie signed with different key must not verify")
	}
}

// 过期 cookie → 当作未登录。
func TestLoginCookieRejectsExpired(t *testing.T) {
	lc := newLoginCookie(cookieSecret)
	// 直接构造 exp 在过去的载荷。
	expired := lc.sign(9, 1) // exp=1(1970),必过期
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: loginCookieName, Value: expired})
	if _, ok := lc.verify(req); ok {
		t.Fatal("expired cookie must not verify")
	}
}

// 无 cookie → 未登录。
func TestLoginCookieMissing(t *testing.T) {
	lc := newLoginCookie(cookieSecret)
	if _, ok := lc.verify(httptest.NewRequest("GET", "/", nil)); ok {
		t.Fatal("missing cookie must not verify")
	}
}

// EntryGate:带有效登录 cookie 命中未知路径 → 302 到 entryPath/,且不计探测。
func TestEntryGateRedirectsLoggedIn(t *testing.T) {
	lc := newLoginCookie(cookieSecret)
	loggedIn := func(r *http.Request) bool { _, ok := lc.verify(r); return ok }
	var probes int
	gate := EntryGate("/secret", nil, loggedIn, func(*http.Request) { probes++ })
	h := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, path := range []string{"/", "/random-xyz"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: loginCookieName, Value: lc.sign(1, farFuture())})

		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("%s: want 302, got %d", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/secret/" {
			t.Errorf("%s: want Location /secret/, got %q", path, loc)
		}
	}
	if probes != 0 {
		t.Fatalf("logged-in redirects must not count as probes, got %d", probes)
	}
}

// EntryGate:无 cookie / 伪造 cookie 命中未知路径 → 404 + 计探测(扫描防护不削弱)。
func TestEntryGateNoCookie404AndProbes(t *testing.T) {
	lc := newLoginCookie(cookieSecret)
	loggedIn := func(r *http.Request) bool { _, ok := lc.verify(r); return ok }
	var probes int
	gate := EntryGate("/secret", nil, loggedIn, func(*http.Request) { probes++ })
	h := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// 无 cookie。
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no cookie: want 404, got %d", rec.Code)
	}

	// 伪造 cookie。
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: loginCookieName, Value: "forged"})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("forged cookie: want 404, got %d", rec.Code)
	}

	if probes != 2 {
		t.Fatalf("want 2 probes (no cookie + forged), got %d", probes)
	}
}

// EntryGate:白名单/入口/静态不受 cookie 逻辑影响,正常放行(不重定向)。
func TestEntryGateLoggedInDoesNotAffectAllowed(t *testing.T) {
	lc := newLoginCookie(cookieSecret)
	loggedIn := func(r *http.Request) bool { _, ok := lc.verify(r); return ok }
	gate := EntryGate("/secret", nil, loggedIn, func(*http.Request) {})
	h := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, p := range []string{"/secret", "/secret/x", "/api/auth/login", "/healthz", "/assets/app.js", "/s/t"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		req.AddCookie(&http.Cookie{Name: loginCookieName, Value: lc.sign(1, farFuture())})
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: allowed path must pass (200), got %d", p, rec.Code)
		}
	}
}

func farFuture() int64 { return 4102444800 } // 2100-01-01

func hasSetCookie(rec *httptest.ResponseRecorder, name string) (*http.Cookie, bool) {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}

func TestLoginSetsCookieLogoutClears(t *testing.T) {
	h := newModuleServerForCookie(t)

	// login 种 cookie。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"pw-123456"}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	c, ok := hasSetCookie(rec, loginCookieName)
	if !ok || c.Value == "" {
		t.Fatal("login must set non-empty xpanel_login cookie")
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie must be HttpOnly + SameSite=Lax, got HttpOnly=%v SameSite=%v", c.HttpOnly, c.SameSite)
	}

	// logout 清 cookie(MaxAge<0)。
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/logout", strings.NewReader(`{"refresh":"whatever"}`))
	h.ServeHTTP(rec, req)
	cc, ok := hasSetCookie(rec, loginCookieName)
	if !ok || cc.MaxAge >= 0 {
		t.Fatalf("logout must clear cookie (MaxAge<0), got ok=%v cookie=%+v", ok, cc)
	}
}

// 端到端:通过真实 NewWithModules 栈,带有效登录 cookie 命中根/未知路径 → 302 到 entryPath/,
// 不计探测;无 cookie → 404。entryPath 为隐藏入口。
func TestEntryGateE2ECookieRedirect(t *testing.T) {
	const entry = "/abc123def456"
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager(cookieSecret)
	svc := auth.NewService(st, jm, auth.NewLockout(5, time.Minute, time.Now))
	if err := svc.Register("admin", "pw-123456", "admin"); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg := module.NewRegistry()
	reg.Register(dashboard.New())
	mgr := module.NewManager(reg, st)
	if err := mgr.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	var banned []string
	probe := NewEntryProbeGuard(0, time.Hour, func(ip string) { banned = append(banned, ip) }, time.Now)
	h := NewWithModules(svc, jm, reg, mgr, nil, nil, nil, entry, probe, cookieSecret, nil, nil, nil)

	lc := newLoginCookie(cookieSecret)
	withCookie := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: loginCookieName, Value: lc.sign(1, farFuture())})
		h.ServeHTTP(rec, req)
		return rec
	}

	for _, p := range []string{"/", "/random-scan-path"} {
		rec := withCookie(p)
		if rec.Code != http.StatusFound {
			t.Fatalf("%s with cookie: want 302, got %d", p, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != entry+"/" {
			t.Errorf("%s: want Location %s/, got %q", p, entry, loc)
		}
	}
	if len(banned) != 0 {
		t.Fatalf("logged-in cookie requests must not count as probes (no ban), got %v", banned)
	}

	// 无 cookie → 404 + 计探测(max=0,任一探测即触发封禁,证明计数生效)。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/random-scan-path", nil)
	req.RemoteAddr = "9.9.9.9:1111"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no cookie: want 404, got %d", rec.Code)
	}
	if len(banned) != 1 || banned[0] != "9.9.9.9" {
		t.Fatalf("no-cookie scan must count as probe and ban, got %v", banned)
	}
}

func newModuleServerForCookie(t *testing.T) http.Handler {
	t.Helper()
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager(cookieSecret)
	svc := auth.NewService(st, jm, auth.NewLockout(5, time.Minute, time.Now))
	if err := svc.Register("admin", "pw-123456", "admin"); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg := module.NewRegistry()
	reg.Register(dashboard.New())
	mgr := module.NewManager(reg, st)
	if err := mgr.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	return NewWithModules(svc, jm, reg, mgr, nil, nil, nil, "/secret", nil, cookieSecret, nil, nil, nil)
}

func decodeJSON(rec *httptest.ResponseRecorder, v any) error {
	return json.Unmarshal(rec.Body.Bytes(), v)
}

func TestRefreshRenewsCookie(t *testing.T) {
	h := newModuleServerForCookie(t)

	// 先登录拿 refresh token。
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"pw-123456"}`)))
	var body struct {
		Refresh string `json:"refresh"`
	}
	if err := decodeJSON(rec, &body); err != nil || body.Refresh == "" {
		t.Fatalf("login response missing refresh: %v (%s)", err, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/auth/refresh", strings.NewReader(`{"refresh":"`+body.Refresh+`"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if c, ok := hasSetCookie(rec, loginCookieName); !ok || c.Value == "" {
		t.Fatal("refresh must renew (set) the login cookie")
	}
}
