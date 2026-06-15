package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestProtectedRouteRequiresToken(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/me", nil)
	newTestServer(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token should give 401, got %d", rec.Code)
	}
}
