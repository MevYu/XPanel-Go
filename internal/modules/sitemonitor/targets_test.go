package sitemonitor

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// newTargetModule 构造一个带 chi router 的模块,role 决定主体角色,audited 计审计次数。
func newTargetModule(t *testing.T, role string, audited *int) (*Module, chi.Router) {
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
	m := New(st, &mockReader{}, deps)
	r := chi.NewRouter()
	m.Routes(r)
	return m, r
}

// doReq 发一个带可选 body/header 的请求,返回 recorder。
func doReq(r chi.Router, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

const validTargetBody = `{"name":"example","url":"https://example.com","interval_sec":60,"timeout_sec":5,"enabled":true}`

func TestCreateTargetOperatorAudits(t *testing.T) {
	audited := 0
	_, r := newTargetModule(t, "operator", &audited)
	rec := doReq(r, "POST", "/targets", validTargetBody, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s)", rec.Code, rec.Body.String())
	}
	if audited != 1 {
		t.Errorf("create must audit once, got %d", audited)
	}
	var got Target
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID == 0 || got.Name != "example" || got.URL != "https://example.com" || !got.Enabled {
		t.Errorf("created target = %+v", got)
	}
}

func TestCreateTargetReadonlyForbidden(t *testing.T) {
	audited := 0
	_, r := newTargetModule(t, "readonly", &audited)
	rec := doReq(r, "POST", "/targets", validTargetBody, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create should be 403, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("forbidden must not audit, got %d", audited)
	}
}

func TestCreateTargetRejectsBadURL(t *testing.T) {
	audited := 0
	_, r := newTargetModule(t, "admin", &audited)
	for _, body := range []string{
		`{"name":"x","url":"ftp://example.com","interval_sec":60,"timeout_sec":5}`,
		`{"name":"x","url":"file:///etc/passwd","interval_sec":60,"timeout_sec":5}`,
		`{"name":"","url":"https://example.com","interval_sec":60,"timeout_sec":5}`,
		`{"name":"x","url":"https://example.com","interval_sec":1,"timeout_sec":5}`,
		`{"name":"x","url":"https://example.com","interval_sec":60,"timeout_sec":999}`,
	} {
		rec := doReq(r, "POST", "/targets", body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s should 400, got %d", body, rec.Code)
		}
	}
	if audited != 0 {
		t.Errorf("rejected creates must not audit, got %d", audited)
	}
}

func TestUpdateTarget(t *testing.T) {
	audited := 0
	m, r := newTargetModule(t, "operator", &audited)
	created, err := m.ms.createTarget(targetInput{Name: "old", URL: "https://a.com", IntervalSec: 60, TimeoutSec: 5, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"name":"new","url":"https://b.com","interval_sec":120,"timeout_sec":10,"enabled":false}`
	rec := doReq(r, "PUT", "/targets/"+itoa(created.ID), body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d (%s)", rec.Code, rec.Body.String())
	}
	got, err := m.ms.getTarget(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "new" || got.URL != "https://b.com" || got.IntervalSec != 120 || got.Enabled {
		t.Errorf("updated = %+v", got)
	}
}

func TestUpdateTargetNotFound(t *testing.T) {
	audited := 0
	_, r := newTargetModule(t, "admin", &audited)
	rec := doReq(r, "PUT", "/targets/999", validTargetBody, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("update missing should 404, got %d", rec.Code)
	}
}

func TestDeleteTargetRequiresConfirmHeader(t *testing.T) {
	audited := 0
	m, r := newTargetModule(t, "admin", &audited)
	created, _ := m.ms.createTarget(targetInput{Name: "x", URL: "https://a.com", IntervalSec: 60, TimeoutSec: 5})
	rec := doReq(r, "DELETE", "/targets/"+itoa(created.ID), "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should be 428, got %d", rec.Code)
	}
}

func TestDeleteTargetRequiresAdmin(t *testing.T) {
	audited := 0
	m, r := newTargetModule(t, "operator", &audited)
	created, _ := m.ms.createTarget(targetInput{Name: "x", URL: "https://a.com", IntervalSec: 60, TimeoutSec: 5})
	rec := doReq(r, "DELETE", "/targets/"+itoa(created.ID), "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator delete should be 403, got %d", rec.Code)
	}
}

func TestDeleteTargetAdminConfirmedAudits(t *testing.T) {
	audited := 0
	m, r := newTargetModule(t, "admin", &audited)
	created, _ := m.ms.createTarget(targetInput{Name: "x", URL: "https://a.com", IntervalSec: 60, TimeoutSec: 5})
	_ = m.ms.insertResult(Result{TargetID: created.ID, CheckedAt: time.Now().Unix(), Up: true, StatusCode: 200})
	rec := doReq(r, "DELETE", "/targets/"+itoa(created.ID), "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin confirmed delete = %d", rec.Code)
	}
	if audited != 1 {
		t.Errorf("delete must audit once, got %d", audited)
	}
	if _, err := m.ms.getTarget(created.ID); err == nil {
		t.Errorf("target should be gone")
	}
	var n int
	_ = m.ms.db.QueryRow(`SELECT COUNT(*) FROM monitor_results WHERE target_id = ?`, created.ID).Scan(&n)
	if n != 0 {
		t.Errorf("results should be cascade-deleted, got %d", n)
	}
}

func TestListTargetsReadableWithSummary(t *testing.T) {
	audited := 0
	m, r := newTargetModule(t, "readonly", &audited)
	created, _ := m.ms.createTarget(targetInput{Name: "x", URL: "https://a.com", IntervalSec: 60, TimeoutSec: 5, Enabled: true})
	// 4 条结果:3 up, 1 down => 可用率 0.75;最近一条为 down/503。
	now := time.Now().Unix()
	_ = m.ms.insertResult(Result{TargetID: created.ID, CheckedAt: now - 3, Up: true, StatusCode: 200, LatencyMS: 10})
	_ = m.ms.insertResult(Result{TargetID: created.ID, CheckedAt: now - 2, Up: true, StatusCode: 200, LatencyMS: 12})
	_ = m.ms.insertResult(Result{TargetID: created.ID, CheckedAt: now - 1, Up: true, StatusCode: 200, LatencyMS: 11})
	_ = m.ms.insertResult(Result{TargetID: created.ID, CheckedAt: now, Up: false, StatusCode: 503, LatencyMS: 30})

	rec := doReq(r, "GET", "/targets", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	var views []TargetView
	if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("views = %d", len(views))
	}
	v := views[0]
	if v.LastStatus != "down" || v.LastCode != 503 || v.LastLatencyMS != 30 || v.LastCheckedAt != now {
		t.Errorf("last summary = %+v", v)
	}
	if v.Availability != 0.75 {
		t.Errorf("availability = %v, want 0.75", v.Availability)
	}
}

func TestListTargetsUnknownWhenNoResults(t *testing.T) {
	audited := 0
	m, r := newTargetModule(t, "readonly", &audited)
	_, _ = m.ms.createTarget(targetInput{Name: "x", URL: "https://a.com", IntervalSec: 60, TimeoutSec: 5})
	rec := doReq(r, "GET", "/targets", "", nil)
	var views []TargetView
	_ = json.Unmarshal(rec.Body.Bytes(), &views)
	if len(views) != 1 || views[0].LastStatus != "unknown" || views[0].LastCheckedAt != 0 {
		t.Errorf("unprobed view = %+v", views)
	}
}

func TestResultsPrunedToCap(t *testing.T) {
	audited := 0
	m, _ := newTargetModule(t, "admin", &audited)
	created, _ := m.ms.createTarget(targetInput{Name: "x", URL: "https://a.com", IntervalSec: 60, TimeoutSec: 5})
	for i := 0; i < maxResultsPerTarget+25; i++ {
		if err := m.ms.insertResult(Result{TargetID: created.ID, CheckedAt: int64(i), Up: true, StatusCode: 200}); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := m.ms.db.QueryRow(`SELECT COUNT(*) FROM monitor_results WHERE target_id = ?`, created.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != maxResultsPerTarget {
		t.Errorf("kept %d results, want %d", n, maxResultsPerTarget)
	}
}

// --- prober ---

// fakeProber 记录被探测的 URL,按预置返回,不触网。
type fakeProber struct {
	code int
	up   bool
	err  error
	mu   chan string // 收集探测过的 URL(用 channel 当线程安全队列)
}

func (f *fakeProber) Probe(_ context.Context, url string, _ time.Duration) (int, bool, error) {
	select {
	case f.mu <- url:
	default:
	}
	return f.code, f.up, f.err
}

func TestProbeOneStoresResult(t *testing.T) {
	audited := 0
	m, _ := newTargetModule(t, "admin", &audited)
	created, _ := m.ms.createTarget(targetInput{Name: "x", URL: "https://a.com", IntervalSec: 60, TimeoutSec: 5, Enabled: true})
	fp := &fakeProber{code: 200, up: true, mu: make(chan string, 1)}
	m.prober.probe = fp
	m.prober.probeOne(context.Background(), created)

	status, code, _, _, avail, err := m.ms.summary(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status != "up" || code != 200 || avail != 1.0 {
		t.Errorf("after probe: status=%s code=%d avail=%v", status, code, avail)
	}
	select {
	case got := <-fp.mu:
		if got != "https://a.com" {
			t.Errorf("probed url = %q", got)
		}
	default:
		t.Errorf("prober was not called")
	}
}

func TestSweepOnlyEnabledAndDueTargets(t *testing.T) {
	audited := 0
	m, _ := newTargetModule(t, "admin", &audited)
	enabled, _ := m.ms.createTarget(targetInput{Name: "on", URL: "https://on.com", IntervalSec: 60, TimeoutSec: 5, Enabled: true})
	_, _ = m.ms.createTarget(targetInput{Name: "off", URL: "https://off.com", IntervalSec: 60, TimeoutSec: 5, Enabled: false})
	fp := &fakeProber{code: 200, up: true, mu: make(chan string, 8)}
	m.prober.probe = fp

	last := make(map[int64]time.Time)
	m.prober.sweep(context.Background(), last)

	// 只有 enabled 目标被探测一次。
	var n int
	_ = m.ms.db.QueryRow(`SELECT COUNT(*) FROM monitor_results`).Scan(&n)
	if n != 1 {
		t.Fatalf("results after sweep = %d, want 1 (only enabled)", n)
	}
	var probedTarget int64
	_ = m.ms.db.QueryRow(`SELECT target_id FROM monitor_results`).Scan(&probedTarget)
	if probedTarget != enabled.ID {
		t.Errorf("probed target = %d, want enabled %d", probedTarget, enabled.ID)
	}

	// 立即再 sweep:间隔(60s)未到,不重复探测。
	m.prober.sweep(context.Background(), last)
	_ = m.ms.db.QueryRow(`SELECT COUNT(*) FROM monitor_results`).Scan(&n)
	if n != 1 {
		t.Errorf("results after 2nd immediate sweep = %d, want still 1 (interval not elapsed)", n)
	}
}

func TestStartStopProberLifecycle(t *testing.T) {
	audited := 0
	m, _ := newTargetModule(t, "admin", &audited)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 重复 Start 幂等,不应 panic 或泄漏。
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Stop 后再 Stop 安全。
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// --- SSRF ---

func TestSafeProberBlocksInternalIPs(t *testing.T) {
	sp := safeProber{}
	for _, target := range []string{
		"http://127.0.0.1/",
		"http://localhost/",
		"http://169.254.169.254/latest/meta-data/", // 云元数据
		"http://10.0.0.1/",
		"http://192.168.1.1/",
		"http://[::1]/",
	} {
		_, up, err := sp.Probe(context.Background(), target, 2*time.Second)
		if up {
			t.Errorf("%s: probe reported up, must be blocked", target)
		}
		if err == nil {
			t.Errorf("%s: expected blocked-address error, got nil", target)
		}
	}
}

func TestIsBlockedIPMatrix(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.0.1", true},
		{"169.254.169.254", true},
		{"169.254.1.1", true},
		{"0.0.0.0", true},
		{"100.64.0.1", true}, // CGNAT
		{"::1", true},
		{"fc00::1", true}, // ULA
		{"fe80::1", true}, // 链路本地
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false}, // Cloudflare DNS over IPv6
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if got := isBlockedIP(ip); got != c.blocked {
			t.Errorf("isBlockedIP(%s) = %v, want %v", c.ip, got, c.blocked)
		}
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
