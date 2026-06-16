package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEntryProbeBansAfterThreshold(t *testing.T) {
	now := time.Unix(1000, 0)
	var banned []string
	g := NewEntryProbeGuard(3, time.Hour, func(ip string) { banned = append(banned, ip) }, func() time.Time { return now })

	ip := "1.2.3.4"
	g.Probe(ip) // 1
	g.Probe(ip) // 2
	g.Probe(ip) // 3 == max, 仍不封(> max 才封)
	if len(banned) != 0 {
		t.Fatalf("at threshold must not ban yet, got %v", banned)
	}
	g.Probe(ip) // 4 > max -> 封
	if len(banned) != 1 || banned[0] != ip {
		t.Fatalf("over threshold should ban once for ip, got %v", banned)
	}
}

func TestEntryProbeUnderThresholdNoBan(t *testing.T) {
	now := time.Unix(1000, 0)
	var banned []string
	g := NewEntryProbeGuard(10, time.Hour, func(ip string) { banned = append(banned, ip) }, func() time.Time { return now })

	for i := 0; i < 10; i++ {
		g.Probe("9.9.9.9")
	}
	if len(banned) != 0 {
		t.Fatalf("10 probes at max 10 must not ban, got %v", banned)
	}
}

func TestEntryProbeWindowExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	var banned []string
	g := NewEntryProbeGuard(3, time.Hour, func(ip string) { banned = append(banned, ip) }, func() time.Time { return now })

	ip := "5.5.5.5"
	g.Probe(ip)
	g.Probe(ip)
	g.Probe(ip)
	// 窗口外:旧命中应衰减,不累加触发封禁。
	now = now.Add(2 * time.Hour)
	g.Probe(ip)
	g.Probe(ip)
	g.Probe(ip)
	if len(banned) != 0 {
		t.Fatalf("probes separated by window must not ban, got %v", banned)
	}
}

// EntryGate 在 404 时调 onProbe,白名单/入口路径放行时不调。
func TestEntryGateProbeHook(t *testing.T) {
	var probes []string
	clientIP := func(r *http.Request) string { return ExtractClientIP(r, nil) }
	gate := EntryGate("/secret", func(r *http.Request) { probes = append(probes, clientIP(r)) })
	h := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	cases := []struct {
		path      string
		wantProbe bool
	}{
		{"/random", true},
		{"/admin", true},
		{"/secret", false},
		{"/secret/x", false},
		{"/api/auth/login", false},
		{"/healthz", false},
		{"/assets/app.js", false},
		{"/s/file", false},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", c.path, nil)
		req.RemoteAddr = "8.8.8.8:1111"
		h.ServeHTTP(rec, req)
	}
	if len(probes) != 2 {
		t.Fatalf("want 2 probes (random, admin), got %d: %v", len(probes), probes)
	}
	for _, p := range probes {
		if p != "8.8.8.8" {
			t.Errorf("probe ip should be RemoteAddr ip, got %q", p)
		}
	}
}

// 受信代理场景:探测计数用 XFF 中的真实客户端 IP。
func TestEntryGateProbeUsesTrustedXFF(t *testing.T) {
	trusted := mustNets(t, "10.0.0.0/8")
	var probes []string
	clientIP := func(r *http.Request) string { return ExtractClientIP(r, trusted) }
	gate := EntryGate("/secret", func(r *http.Request) { probes = append(probes, clientIP(r)) })
	h := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/scan", nil)
	req.RemoteAddr = "10.1.2.3:9999" // 受信代理
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(probes) != 1 || probes[0] != "203.0.113.7" {
		t.Fatalf("want real client ip 203.0.113.7 from XFF, got %v", probes)
	}
}
