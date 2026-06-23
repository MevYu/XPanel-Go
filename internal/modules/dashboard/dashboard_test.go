package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// newTestModule 建内存 DB 模块,Principal 由 role 决定(测 RBAC)。
func newTestModule(t *testing.T, role string) *Module {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, Deps{Principal: func(*http.Request) (int64, string) { return 1, role }})
}

func TestMetaAlwaysOn(t *testing.T) {
	m := newTestModule(t, "admin")
	if m.Meta().ID != "dashboard" || !m.Meta().AlwaysOn {
		t.Errorf("dashboard must be id=dashboard AlwaysOn, got %+v", m.Meta())
	}
}

func TestMetricsEndpoint(t *testing.T) {
	r := chi.NewRouter()
	newTestModule(t, "admin").Routes(r)
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
	newTestModule(t, "admin").Routes(r)
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
	newTestModule(t, "admin").Routes(r)
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
	newTestModule(t, "admin").Routes(r)
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
	newTestModule(t, "admin").Routes(r)
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

// serveHomeApps 用给定角色装好路由,跑一次请求,返回响应记录。
func serveHomeApps(t *testing.T, m *Module, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	m.Routes(r)
	var rb *bytes.Buffer
	if body == "" {
		rb = bytes.NewBufferString("")
	} else {
		rb = bytes.NewBufferString(body)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, "/home-apps", rb))
	return rec
}

func decodeModules(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var out homeAppsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body not JSON: %v: %s", err, rec.Body.String())
	}
	return out.Modules
}

func TestHomeAppsGetEmpty(t *testing.T) {
	m := newTestModule(t, "admin")
	rec := serveHomeApps(t, m, "GET", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status %d", rec.Code)
	}
	mods := decodeModules(t, rec)
	if mods == nil || len(mods) != 0 {
		t.Errorf("empty config must return [], got %#v: %s", mods, rec.Body.String())
	}
	if !contains(rec.Body.String(), "[]") {
		t.Errorf("empty modules must serialize as [], got %s", rec.Body.String())
	}
}

func TestHomeAppsPutThenGet(t *testing.T) {
	m := newTestModule(t, "admin")
	put := serveHomeApps(t, m, "PUT", `{"modules":["sites","database","supervisor"]}`)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status %d: %s", put.Code, put.Body.String())
	}
	get := serveHomeApps(t, m, "GET", "")
	mods := decodeModules(t, get)
	want := []string{"sites", "database", "supervisor"}
	if len(mods) != len(want) {
		t.Fatalf("readback mismatch: got %#v want %#v", mods, want)
	}
	for i := range want {
		if mods[i] != want[i] {
			t.Errorf("order mismatch at %d: got %q want %q", i, mods[i], want[i])
		}
	}
}

func TestHomeAppsPutNonAdminForbidden(t *testing.T) {
	for _, role := range []string{"operator", "viewer", ""} {
		m := newTestModule(t, role)
		rec := serveHomeApps(t, m, "PUT", `{"modules":["sites"]}`)
		if rec.Code != http.StatusForbidden {
			t.Errorf("role %q PUT should be 403, got %d", role, rec.Code)
		}
	}
}

func TestHomeAppsPutRejectsBadBody(t *testing.T) {
	cases := map[string]string{
		"not json":   `{`,
		"empty id":   `{"modules":["sites",""]}`,
		"non-array":  `{"modules":"sites"}`,
		"wrong elem": `{"modules":[1,2,3]}`,
	}
	for name, body := range cases {
		m := newTestModule(t, "admin")
		rec := serveHomeApps(t, m, "PUT", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: PUT should be 400, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestHomeAppsPutRejectsTooMany(t *testing.T) {
	ids := make([]string, maxHomeApps+1)
	for i := range ids {
		ids[i] = "m"
	}
	raw, _ := json.Marshal(homeAppsBody{Modules: ids})
	m := newTestModule(t, "admin")
	rec := serveHomeApps(t, m, "PUT", string(raw))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized list should be 400, got %d", rec.Code)
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
