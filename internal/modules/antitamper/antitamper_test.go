package antitamper

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestModule(t *testing.T, role string, audited *int) *Module {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(userID *int64, action, detail, ip string) { *audited++ },
	})
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func router(m *Module) *chi.Mux {
	r := chi.NewRouter()
	m.Routes(r)
	return r
}

func TestMetaSwitchableSecurity(t *testing.T) {
	m := newTestModule(t, "admin", new(int))
	meta := m.Meta()
	if meta.ID != "antitamper" || meta.AlwaysOn || meta.Category != "安全" {
		t.Fatalf("unexpected meta: %+v", meta)
	}
}

func TestSettingsRequiresAdmin(t *testing.T) {
	audited := 0
	m := newTestModule(t, "operator", &audited)
	r := router(m)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/settings", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator GET settings should be 403, got %d", rec.Code)
	}
}

func TestPutSettingsRejectsRelativeDir(t *testing.T) {
	audited := 0
	m := newTestModule(t, "admin", &audited)
	r := router(m)

	body, _ := json.Marshal(Settings{ProtectedDirs: []string{"../../etc"}, IntervalSec: 60})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/settings", bytesReader(body))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("relative protected dir must be 400, got %d", rec.Code)
	}
}

func TestPutSettingsAdminAudits(t *testing.T) {
	audited := 0
	m := newTestModule(t, "admin", &audited)
	r := router(m)

	body, _ := json.Marshal(Settings{ProtectedDirs: []string{"/www/site"}, IntervalSec: 120})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/settings", bytesReader(body))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin PUT settings should be 200, got %d", rec.Code)
	}
	if audited != 1 {
		t.Fatalf("admin settings change must audit once, got %d", audited)
	}
}

func TestRebuildRequiresAdmin(t *testing.T) {
	audited := 0
	m := newTestModule(t, "operator", &audited)
	r := router(m)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/baseline", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator rebuild should be 403, got %d", rec.Code)
	}
	if audited != 0 {
		t.Fatalf("forbidden request must not audit, got %d", audited)
	}
}

func TestPauseResumeFlow(t *testing.T) {
	audited := 0
	m := newTestModule(t, "admin", &audited)
	r := router(m)

	for _, verb := range []string{"pause", "resume"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/"+verb, nil)
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s should be 200, got %d", verb, rec.Code)
		}
	}
	s, _ := m.as.getSettings()
	if s.Paused {
		t.Fatal("after resume, must not be paused")
	}
}

// TestEndToEndTamperDetection: set protected dir, rebuild baseline via HTTP,
// mutate a file, run one scan pass, assert the modification is recorded.
func TestEndToEndTamperDetection(t *testing.T) {
	audited := 0
	m := newTestModule(t, "admin", &audited)
	r := router(m)

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.php"), "original")

	// configure protected dir + short interval
	body, _ := json.Marshal(Settings{ProtectedDirs: []string{dir}, IntervalSec: 60})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("PUT", "/settings", bytesReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("settings PUT: %d", rec.Code)
	}

	// build baseline
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/baseline", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("baseline POST: %d", rec.Code)
	}

	// tamper
	writeFile(t, filepath.Join(dir, "config.php"), "HACKED")
	writeFile(t, filepath.Join(dir, "shell.php"), "evil")

	// one scan pass (deterministic, no goroutine timing)
	if err := m.mon.scanOnce(context.Background()); err != nil {
		t.Fatalf("scanOnce: %v", err)
	}

	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/events", nil))
	var evs []Event
	json.NewDecoder(rec.Body).Decode(&evs)
	if len(evs) != 2 {
		t.Fatalf("want 2 tamper events (modified+added), got %d: %+v", len(evs), evs)
	}
}

func TestPausedSkipsDetection(t *testing.T) {
	audited := 0
	m := newTestModule(t, "admin", &audited)

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "x")
	m.as.putSettings(Settings{ProtectedDirs: []string{dir}, IntervalSec: 60, Paused: true})
	states, _ := scanDirs(context.Background(), []string{dir}, nil)
	m.as.replaceBaseline(states)

	writeFile(t, filepath.Join(dir, "a.txt"), "tampered")
	if err := m.mon.scanOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	evs, _ := m.as.listEvents(10)
	if len(evs) != 0 {
		t.Fatalf("paused must skip detection, got %d events", len(evs))
	}
}

// TestStartStopNoLeak: Start spawns the monitor goroutine and returns immediately;
// Stop cancels and waits for clean exit. Run with -race to catch leaks/races.
func TestStartStopNoLeak(t *testing.T) {
	audited := 0
	m := newTestModule(t, "admin", &audited)

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "x")
	// tiny interval so the loop actually iterates while running
	m.as.putSettings(Settings{ProtectedDirs: []string{dir}, IntervalSec: 1, Paused: false})

	done := make(chan struct{})
	go func() {
		if err := m.Start(context.Background()); err != nil {
			t.Errorf("Start: %v", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start did not return promptly (must spawn goroutine and return)")
	}

	// Stop must return (goroutine drained) without hanging.
	stopped := make(chan struct{})
	go func() { _ = m.Stop(context.Background()); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop hung: monitor goroutine not draining on cancel")
	}

	// idempotent stop
	_ = m.Stop(context.Background())
}

func TestScanDirsRejectsNonexistent(t *testing.T) {
	_, err := scanDirs(context.Background(), []string{"/no/such/path/xpanel-test"}, nil)
	if err == nil {
		t.Fatal("scanDirs must error on nonexistent protected dir")
	}
}

// TestScanDirsRejectsSymlinkEscape: a protected dir that is a symlink pointing
// outside itself must be rejected by SafeJoin (path-traversal defense).
func TestScanDirsRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	// SafeJoin(link, ".") resolves link's real path; since link != its resolved
	// target, escape is detected.
	if _, err := scanDirs(context.Background(), []string{link}, nil); err == nil {
		t.Fatal("symlinked protected dir must be rejected")
	}
}

// scanOnce 在扫描中途遇 ctx 取消必须及时返回。这保证 stop()(cancel+<-done)
// 不被慢扫描阻塞,从而持锁调 stop 的 Manager 不会冻结全模块启停。
func TestScanOnceReturnsPromptlyOnCancel(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2000; i++ {
		writeFile(t, filepath.Join(dir, "f"+itoa(i)+".bin"), "payload-payload-payload")
	}
	m := newTestModule(t, "admin", new(int))
	m.as.putSettings(Settings{ProtectedDirs: []string{dir}, IntervalSec: 60, Paused: false})
	states, _ := scanDirs(context.Background(), []string{dir}, nil)
	m.as.replaceBaseline(states)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 取消后扫描应在文件间立即 bail
	done := make(chan error, 1)
	go func() { done <- m.mon.scanOnce(ctx) }()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("scanOnce on canceled ctx = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scanOnce did not bail on cancel: blocked past 5s")
	}
}
