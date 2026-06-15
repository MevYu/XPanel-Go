package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimitBlocksBurst(t *testing.T) {
	rl := NewRateLimiter(2) // 每 IP 容量 2
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	call := func() int {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "9.9.9.9:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if call() != 200 || call() != 200 {
		t.Fatal("first 2 requests should pass")
	}
	if call() != http.StatusTooManyRequests {
		t.Error("3rd request should be rate-limited")
	}
}
