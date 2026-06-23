package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestMetaAlwaysOn(t *testing.T) {
	m := New()
	if m.Meta().ID != "dashboard" || !m.Meta().AlwaysOn {
		t.Errorf("dashboard must be id=dashboard AlwaysOn, got %+v", m.Meta())
	}
}

func TestMetricsEndpoint(t *testing.T) {
	r := chi.NewRouter()
	New().Routes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status %d", rec.Code)
	}
	if !contains(rec.Body.String(), "mem_total") {
		t.Errorf("metrics body missing mem_total: %s", rec.Body.String())
	}
}

func TestDetailMetricsEndpoint(t *testing.T) {
	r := chi.NewRouter()
	New().Routes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics/detail", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, key := range []string{"cpu_per_core", "network", "disk_io", "uptime_sec", "swap_total"} {
		if !contains(body, key) {
			t.Errorf("detail body missing %q: %s", key, body)
		}
	}
}

func TestProcessesEndpoint(t *testing.T) {
	r := chi.NewRouter()
	New().Routes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/processes?limit=3", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("processes status %d", rec.Code)
	}
	body := rec.Body.String()
	if !contains(body, "pid") || !contains(body, "cpu_percent") {
		t.Errorf("processes body missing keys: %s", body)
	}
}

func TestSysInfoEndpoint(t *testing.T) {
	r := chi.NewRouter()
	New().Routes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/sysinfo", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("sysinfo status %d", rec.Code)
	}
	var info map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("sysinfo body not JSON object: %v: %s", err, rec.Body.String())
	}
	for _, key := range []string{"hostname", "os", "kernel", "arch", "cpu_model", "cpu_physical_cores", "cpu_logical_cores", "private_ip", "public_ip", "panel_version"} {
		if _, ok := info[key]; !ok {
			t.Errorf("sysinfo body missing key %q: %s", key, rec.Body.String())
		}
	}
	if info["hostname"] == "" {
		t.Errorf("sysinfo hostname should be non-empty in test runtime: %s", rec.Body.String())
	}
	if info["panel_version"] == "" {
		t.Errorf("sysinfo panel_version should be non-empty: %s", rec.Body.String())
	}
	if st, ok := info["server_time"].(float64); !ok || st <= 0 {
		t.Errorf("sysinfo server_time should be a positive unix timestamp: %s", rec.Body.String())
	}
}

func TestDiskPartitionsEndpoint(t *testing.T) {
	r := chi.NewRouter()
	New().Routes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/disk-partitions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("disk-partitions status %d", rec.Code)
	}
	var parts []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parts); err != nil {
		t.Fatalf("disk-partitions body not JSON array: %v: %s", err, rec.Body.String())
	}
	for i, p := range parts {
		for _, key := range []string{"device", "mountpoint", "fstype", "total", "used", "free", "used_percent"} {
			if _, ok := p[key]; !ok {
				t.Errorf("partition[%d] missing key %q: %s", i, key, rec.Body.String())
			}
		}
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
