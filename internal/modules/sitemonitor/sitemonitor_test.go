package sitemonitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockReader 返回固定样本日志行,不触碰文件系统;记录最后一次被请求的 path 供穿越断言。
type mockReader struct {
	lines    []string
	lastPath string
}

func (m *mockReader) TailLines(path string, maxLines int) ([]string, error) {
	m.lastPath = path
	if maxLines > 0 && len(m.lines) > maxLines {
		return m.lines[len(m.lines)-maxLines:], nil
	}
	return m.lines, nil
}

var sampleLog = []string{
	`1.1.1.1 - - [10/Oct/2023:10:30:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "UA1"`,
	`1.1.1.1 - - [10/Oct/2023:10:31:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "UA1"`,
	`2.2.2.2 - - [10/Oct/2023:11:05:00 +0000] "GET /b HTTP/1.1" 404 0 "-" "UA2"`,
	`3.3.3.3 - - [10/Oct/2023:11:10:00 +0000] "POST /a HTTP/1.1" 500 5 "-" "UA1"`,
}

func newTestModule(t *testing.T, role string, audited *int) (*Module, chi.Router, *mockReader) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(_ *int64, _, _, _ string) { *audited++ },
	}
	mr := &mockReader{lines: sampleLog}
	m := New(st, mr, deps)
	// 设置一个 LogRoot 以便 resolveLogPath 通过(默认 AccessLog 为绝对路径,SafeJoin 词法限定)。
	if err := m.ms.setSettings(Settings{LogRoot: "/tmp", AccessLog: "/tmp/access.log", MaxLines: 1000}); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	m.Routes(r)
	return m, r, mr
}

func TestMetaSwitchable(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	meta := m.Meta()
	if meta.ID != "sitemonitor" || meta.AlwaysOn {
		t.Errorf("must be id=sitemonitor, not AlwaysOn, got %+v", meta)
	}
	if meta.Category != "网站" || meta.Name != "网站监控" {
		t.Errorf("meta = %+v", meta)
	}
}

func TestNavAndHealth(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	nav := m.Nav()
	if len(nav) != 1 || nav[0].Path != "/sitemonitor" {
		t.Errorf("nav = %+v", nav)
	}
	if err := m.HealthCheck(); err != nil {
		t.Errorf("health should pass: %v", err)
	}
}

func TestOverviewReadable(t *testing.T) {
	_, r, _ := newTestModule(t, "readonly", new(int))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("overview = %d", rec.Code)
	}
	var rep Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.TotalRequests != 4 {
		t.Errorf("total = %d", rep.TotalRequests)
	}
	if rep.UniqueIPs != 3 {
		t.Errorf("uv = %d", rep.UniqueIPs)
	}
	if rep.Status.XX2 != 2 || rep.Status.XX4 != 1 || rep.Status.XX5 != 1 {
		t.Errorf("status = %+v", rep.Status)
	}
}

func TestOverviewTimeRange(t *testing.T) {
	_, r, _ := newTestModule(t, "readonly", new(int))
	rec := httptest.NewRecorder()
	// 只取 11:00 之后的两条。
	req := httptest.NewRequest("GET", "/overview?from=2023-10-10T11:00:00Z", nil)
	r.ServeHTTP(rec, req)
	var rep Report
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep.TotalRequests != 2 {
		t.Errorf("time-filtered total = %d", rep.TotalRequests)
	}
}

func TestSitesEndpoint(t *testing.T) {
	_, r, _ := newTestModule(t, "readonly", new(int))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/sites", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("sites = %d", rec.Code)
	}
	var sites []SiteStat
	_ = json.Unmarshal(rec.Body.Bytes(), &sites)
	// combined 日志无 host 字段,聚合到 "-"。
	if len(sites) != 1 || sites[0].Requests != 4 {
		t.Errorf("sites = %+v", sites)
	}
}

func TestTrendEndpoint(t *testing.T) {
	_, r, _ := newTestModule(t, "readonly", new(int))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/trend?granularity=hour", nil))
	var pts []TrendPoint
	_ = json.Unmarshal(rec.Body.Bytes(), &pts)
	if len(pts) != 2 {
		t.Fatalf("hourly trend buckets = %d (%+v)", len(pts), pts)
	}
	if pts[0].Requests != 2 {
		t.Errorf("first bucket = %+v", pts[0])
	}
}

func TestTopEndpoint(t *testing.T) {
	_, r, _ := newTestModule(t, "readonly", new(int))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/top?kind=url&top=1", nil))
	var top []Count
	_ = json.Unmarshal(rec.Body.Bytes(), &top)
	if len(top) != 1 || top[0].Key != "/a" || top[0].Count != 3 {
		t.Errorf("top url = %+v", top)
	}
}

func TestPutSettingsRequiresAdmin(t *testing.T) {
	audited := 0
	_, r, _ := newTestModule(t, "readonly", &audited)
	body := `{"log_root":"/var/log/nginx","access_log":"/var/log/nginx/access.log","max_lines":1000}`
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("PUT", "/settings", strings.NewReader(body)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly PUT settings should be 403, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("forbidden must not audit, got %d", audited)
	}
}

func TestPutSettingsAdminAudits(t *testing.T) {
	audited := 0
	_, r, _ := newTestModule(t, "admin", &audited)
	body := `{"log_root":"/var/log/nginx","access_log":"/var/log/nginx/access.log","max_lines":1000}`
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("PUT", "/settings", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin PUT settings = %d", rec.Code)
	}
	if audited != 1 {
		t.Errorf("admin settings update must audit once, got %d", audited)
	}
}

func TestPutSettingsRejectsBadPath(t *testing.T) {
	_, r, _ := newTestModule(t, "admin", new(int))
	body := `{"log_root":"relative","access_log":"/a","max_lines":1}`
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("PUT", "/settings", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad log_root should 400, got %d", rec.Code)
	}
}

func TestSnapshotRequiresAdmin(t *testing.T) {
	audited := 0
	_, r, _ := newTestModule(t, "operator", &audited)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/snapshot", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin snapshot should be 403, got %d", rec.Code)
	}
}

func TestSnapshotAdminPersists(t *testing.T) {
	audited := 0
	m, r, _ := newTestModule(t, "admin", &audited)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/snapshot", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin snapshot = %d", rec.Code)
	}
	if audited != 1 {
		t.Errorf("snapshot must audit once, got %d", audited)
	}
	var n int
	if err := m.ms.db.QueryRow(`SELECT COUNT(*) FROM sitemonitor_snapshots`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("snapshot rows = %d", n)
	}
}

func TestPathTraversalConfinedViaQuery(t *testing.T) {
	_, r, mr := newTestModule(t, "admin", new(int))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/overview?log=../../etc/passwd", nil))
	// SafeJoin 把穿越中和到 LogRoot(/tmp)子树内,reader 永不收到逃逸路径。
	if !strings.HasPrefix(mr.lastPath, "/tmp") {
		t.Errorf("traversal escaped LogRoot, reader got %q", mr.lastPath)
	}
}

func TestGetSettingsDefault(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := New(st, &mockReader{}, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, "readonly" },
		Audit:     func(_ *int64, _, _, _ string) {},
	})
	r := chi.NewRouter()
	m.Routes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/settings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get settings = %d", rec.Code)
	}
	var s Settings
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	if s.LogRoot != "/www/wwwlogs" {
		t.Errorf("default log_root = %q", s.LogRoot)
	}
}
