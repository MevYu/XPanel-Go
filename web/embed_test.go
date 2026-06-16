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
