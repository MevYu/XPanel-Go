package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		nets = append(nets, n)
	}
	return nets
}

func reqWith(remote, xff, xreal string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if xreal != "" {
		r.Header.Set("X-Real-IP", xreal)
	}
	return r
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name    string
		trusted []*net.IPNet
		remote  string
		xff     string
		xreal   string
		want    string
	}{
		{
			name:   "no trusted proxies, with XFF -> RemoteAddr",
			remote: "203.0.113.9:5555",
			xff:    "1.2.3.4",
			want:   "203.0.113.9",
		},
		{
			name:   "no trusted proxies, no XFF -> RemoteAddr",
			remote: "203.0.113.9:5555",
			want:   "203.0.113.9",
		},
		{
			name:    "trusted proxy, XFF client + proxy -> real client",
			trusted: mustNets(t, "10.0.0.0/8"),
			remote:  "10.0.0.1:443",
			xff:     "1.2.3.4, 10.0.0.1",
			want:    "1.2.3.4",
		},
		{
			name:    "untrusted remote with forged XFF -> RemoteAddr (anti-spoof)",
			trusted: mustNets(t, "10.0.0.0/8"),
			remote:  "203.0.113.9:5555",
			xff:     "1.2.3.4",
			want:    "203.0.113.9",
		},
		{
			name:    "multi-level trusted chain -> rightmost untrusted",
			trusted: mustNets(t, "10.0.0.0/8", "192.168.0.0/16"),
			remote:  "10.0.0.1:443",
			xff:     "8.8.8.8, 192.168.1.1, 10.0.0.2",
			want:    "8.8.8.8",
		},
		{
			name:    "trusted remote, XFF all trusted -> X-Real-IP fallback",
			trusted: mustNets(t, "10.0.0.0/8"),
			remote:  "10.0.0.1:443",
			xff:     "10.0.0.2, 10.0.0.1",
			xreal:   "5.6.7.8",
			want:    "5.6.7.8",
		},
		{
			name:    "trusted remote, no XFF, no X-Real-IP -> RemoteAddr",
			trusted: mustNets(t, "10.0.0.0/8"),
			remote:  "10.0.0.1:443",
			want:    "10.0.0.1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractClientIP(reqWith(tc.remote, tc.xff, tc.xreal), tc.trusted)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRateLimiterKeyUsesRealIP 端到端验证:受信代理后,限速 key 用解析后的真实客户端 IP,
// 不同真实客户端各自独立计数(而非共享反代 IP 的桶)。
func TestRateLimiterKeyUsesRealIP(t *testing.T) {
	trusted := mustNets(t, "10.0.0.0/8")
	rl := NewRateLimiterWithClientIP(1, clientIPFunc(trusted))
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	call := func(xff string) int {
		req := reqWith("10.0.0.1:443", xff, "")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// client A: first ok, second limited (burst 1).
	if call("1.1.1.1, 10.0.0.1") != http.StatusOK {
		t.Fatal("client A first request should pass")
	}
	if call("1.1.1.1, 10.0.0.1") != http.StatusTooManyRequests {
		t.Fatal("client A second request should be limited")
	}
	// client B (different real IP via XFF, same proxy) still has its own bucket.
	if call("2.2.2.2, 10.0.0.1") != http.StatusOK {
		t.Fatal("client B should have an independent bucket keyed by real IP")
	}
}

// TestIPBanKeyUsesRealIP 端到端验证:封禁判定用解析后的真实客户端 IP;
// 伪造 XFF 来自非受信 remote 时被忽略(用 RemoteAddr),无法借伪造头逃避封禁。
func TestIPBanKeyUsesRealIP(t *testing.T) {
	trusted := mustNets(t, "10.0.0.0/8")
	bannedIP := "1.2.3.4"
	captured := ""
	banned := func(ip string) bool {
		captured = ip
		return ip == bannedIP
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := IPBanMiddleware(banned, clientIPFunc(trusted))(ok)

	// Behind trusted proxy: real client 1.2.3.4 is banned.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqWith("10.0.0.1:443", "1.2.3.4, 10.0.0.1", ""))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("banned real IP should be rejected, got %d", rec.Code)
	}
	if captured != "1.2.3.4" {
		t.Fatalf("ban check should use real IP, got %q", captured)
	}

	// Untrusted remote forging XFF=1.2.3.4: XFF ignored, RemoteAddr used -> not banned.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqWith("203.0.113.9:5555", "1.2.3.4", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("forged XFF must be ignored from untrusted remote, got %d", rec.Code)
	}
	if captured != "203.0.113.9" {
		t.Fatalf("ban check should use RemoteAddr for untrusted remote, got %q", captured)
	}
}
