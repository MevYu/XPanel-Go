package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesIndexFallback(t *testing.T) {
	h := Handler()
	for _, p := range []string{"/", "/dashboard", "/some/spa/route"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: code=%d", p, rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("%s: content-type=%q", p, ct)
		}
	}
}

func TestHandlerWithBaseInjectsBase(t *testing.T) {
	const entry = "/abc123def456"
	h := HandlerWithBase(entry)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, entry+"/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("entry index code=%d", rr.Code)
	}
	body := rr.Body.String()
	want := `window.__XPANEL_BASE__="` + entry + `";`
	if !strings.Contains(body, want) {
		t.Fatalf("index must inject base script %q, body=%q", want, body)
	}
}

// TestHandlerWithBaseInjectsNonce 断言:当 context 带 nonce 时,注入的 base
// 内联 script 标签带上同一个 nonce(配合 CSP script-src 'nonce-...' 放行)。
func TestHandlerWithBaseInjectsNonce(t *testing.T) {
	const entry = "/abc123def456"
	const nonce = "TESTNONCE123=="
	h := HandlerWithBase(entry)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, entry+"/", nil)
	req = req.WithContext(WithNonce(context.Background(), nonce))
	h.ServeHTTP(rr, req)

	body := rr.Body.String()
	want := `<script nonce="` + nonce + `">window.__XPANEL_BASE__="` + entry + `";</script>`
	if !strings.Contains(body, want) {
		t.Fatalf("index must inject nonced base script %q, body=%q", want, body)
	}
}

// TestNonceRoundTrip 断言 WithNonce/NonceFromContext 配对;缺省 context 返回空。
func TestNonceRoundTrip(t *testing.T) {
	if got := NonceFromContext(context.Background()); got != "" {
		t.Fatalf("empty context nonce = %q, want \"\"", got)
	}
	ctx := WithNonce(context.Background(), "abc")
	if got := NonceFromContext(ctx); got != "abc" {
		t.Fatalf("nonce round-trip = %q, want abc", got)
	}
}

func TestHandlerWithBaseServesAssets(t *testing.T) {
	h := HandlerWithBase("/abc123def456")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/assets/does-not-exist.js", nil))
	// missing asset falls back to index (200), real asset would be served by FileServer.
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestHandlerMissingAssetFallsBackNoCache(t *testing.T) {
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/assets/does-not-exist.js", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d", rr.Code)
	}
	// Missing asset must not get the immutable cache header (it served index).
	if cc := rr.Header().Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Fatalf("missing asset got immutable cache: %q", cc)
	}
}
