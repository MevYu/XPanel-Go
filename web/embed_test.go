package webui

import (
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
