package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	webui "github.com/MevYu/XPanel-Go/web"
)

func TestSecurityHeaders(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	want := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s: want %q, got %q", k, v, got)
		}
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("CSP header missing")
	}
}

func TestSecurityHeadersCSPDirectives(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	csp := rec.Header().Get("Content-Security-Policy")

	for _, frag := range []string{
		"script-src 'self' 'nonce-",
		"style-src 'self' 'unsafe-inline'",
		"font-src 'self' data:",
		"img-src 'self' data:",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, frag) {
			t.Errorf("CSP missing %q; got %q", frag, csp)
		}
	}
	// script-src 不得放开 unsafe-inline(nonce 方案的全部意义)。
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("script-src must not allow unsafe-inline; got %q", csp)
	}
}

func TestSecurityHeadersNoncePerResponseUnique(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		nonce := extractNonce(t, rec.Header().Get("Content-Security-Policy"))
		if nonce == "" {
			t.Fatalf("no nonce in CSP: %q", rec.Header().Get("Content-Security-Policy"))
		}
		if seen[nonce] {
			t.Fatalf("nonce reused across responses: %q", nonce)
		}
		seen[nonce] = true
	}
}

// TestSecurityHeadersNonceInContext 断言中间件把 nonce 放进 context,
// 且与 CSP 头里的 nonce 一致——下游 SPA handler 据此给内联 script 打同一个 nonce。
func TestSecurityHeadersNonceInContext(t *testing.T) {
	var ctxNonce string
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxNonce = webui.NonceFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	headerNonce := extractNonce(t, rec.Header().Get("Content-Security-Policy"))
	if ctxNonce == "" {
		t.Fatal("nonce not propagated to context")
	}
	if ctxNonce != headerNonce {
		t.Fatalf("context nonce %q != header nonce %q", ctxNonce, headerNonce)
	}
}

func extractNonce(t *testing.T, csp string) string {
	t.Helper()
	const marker = "'nonce-"
	i := strings.Index(csp, marker)
	if i < 0 {
		return ""
	}
	rest := csp[i+len(marker):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return ""
	}
	return rest[:j]
}
