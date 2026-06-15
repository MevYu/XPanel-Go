package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	svc := auth.NewService(st, jm, auth.NewLockout(5, time.Minute, time.Now))
	svc.Register("admin", "pw-123456", "admin")
	return New(svc, jm)
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer(t).ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
}

func TestLoginHandlerReturnsTokens(t *testing.T) {
	rec := httptest.NewRecorder()
	body := `{"username":"admin","password":"pw-123456"}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	newTestServer(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "access") {
		t.Errorf("response missing access token: %s", rec.Body.String())
	}
}

func TestLoginHandlerRejectsBadPassword(t *testing.T) {
	rec := httptest.NewRecorder()
	body := `{"username":"admin","password":"nope"}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	newTestServer(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}

// loginServerWithTOTP 装配仅含 /api/auth/login 的服务,注入给定的 2FA 校验器。
func loginServerWithTOTP(t *testing.T, totp loginTOTPVerifier) http.Handler {
	t.Helper()
	st, _ := store.Open(":memory:")
	jm := auth.NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	svc := auth.NewService(st, jm, auth.NewLockout(3, time.Minute, time.Now))
	svc.Register("admin", "pw-123456", "admin")
	ah := &authHandlers{svc: svc, totp: totp}
	r := chi.NewRouter()
	r.Post("/api/auth/login", ah.login)
	return r
}

func postLogin(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	h.ServeHTTP(rec, req)
	return rec
}

// 用户未启用 2FA:仅密码即可登录(回归)。
func TestLogin2FA_NotEnabledLogsIn(t *testing.T) {
	h := loginServerWithTOTP(t, func(int64, string) (bool, bool, error) {
		return false, false, nil
	})
	rec := postLogin(t, h, `{"username":"admin","password":"pw-123456"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "access") {
		t.Errorf("missing access token: %s", rec.Body.String())
	}
}

// 启用 2FA,仅密码无 code → 401 2fa_required。
func TestLogin2FA_RequiredWhenCodeMissing(t *testing.T) {
	h := loginServerWithTOTP(t, func(_ int64, code string) (bool, bool, error) {
		return true, code == "123456", nil
	})
	rec := postLogin(t, h, `{"username":"admin","password":"pw-123456"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2fa_required") {
		t.Errorf("want 2fa_required body, got %s", rec.Body.String())
	}
}

// 启用 2FA,密码+正确 code → 成功。
func TestLogin2FA_ValidCodeLogsIn(t *testing.T) {
	h := loginServerWithTOTP(t, func(_ int64, code string) (bool, bool, error) {
		return true, code == "123456", nil
	})
	rec := postLogin(t, h, `{"username":"admin","password":"pw-123456","totp":"123456"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "access") {
		t.Errorf("missing access token: %s", rec.Body.String())
	}
}

// 启用 2FA,密码+错 code → 401 2fa_required。
func TestLogin2FA_WrongCodeRejected(t *testing.T) {
	h := loginServerWithTOTP(t, func(_ int64, code string) (bool, bool, error) {
		return true, code == "123456", nil
	})
	rec := postLogin(t, h, `{"username":"admin","password":"pw-123456","totp":"999999"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2fa_required") {
		t.Errorf("want 2fa_required body, got %s", rec.Body.String())
	}
}

// 密码错 → 普通 401(无 2fa_required)且计入锁定。
func TestLogin2FA_WrongPasswordPlain401AndLocks(t *testing.T) {
	h := loginServerWithTOTP(t, func(int64, string) (bool, bool, error) {
		return true, false, nil
	})
	for i := 0; i < 3; i++ {
		rec := postLogin(t, h, `{"username":"admin","password":"wrong"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "2fa_required") {
			t.Errorf("wrong password must not return 2fa_required")
		}
	}
	// 3 次密码错后锁定:正确密码也被拒。
	rec := postLogin(t, h, `{"username":"admin","password":"pw-123456","totp":"x"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("after lockout want 401, got %d", rec.Code)
	}
}

// 2fa_required 不计入锁定:正确密码缺 code 多次后,补上正确 code 仍能登录。
func TestLogin2FA_RequiredDoesNotLock(t *testing.T) {
	h := loginServerWithTOTP(t, func(_ int64, code string) (bool, bool, error) {
		return true, code == "123456", nil
	})
	for i := 0; i < 5; i++ {
		rec := postLogin(t, h, `{"username":"admin","password":"pw-123456"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, rec.Code)
		}
	}
	rec := postLogin(t, h, `{"username":"admin","password":"pw-123456","totp":"123456"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("2fa_required must not lock; want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestProtectedRouteRequiresToken(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/me", nil)
	newTestServer(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token should give 401, got %d", rec.Code)
	}
}
