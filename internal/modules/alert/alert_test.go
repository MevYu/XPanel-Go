package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestModule(t *testing.T, role string) (*Module, *int) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	audited := new(int)
	m := New("test-secret", st, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	})
	return m, audited
}

func do(m *Module, method, target, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	m.Routes(r)
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, rd)
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRBACRuleWriteRequiresOperator(t *testing.T) {
	m, _ := newTestModule(t, "viewer")
	body := `{"name":"x","metric":"cpu","comparator":"gt","threshold":80,"channel_id":1}`
	if w := do(m, http.MethodPost, "/rules", body); w.Code != http.StatusForbidden {
		t.Errorf("viewer creating rule = %d, want 403", w.Code)
	}
}

func TestRBACChannelWriteRequiresAdmin(t *testing.T) {
	m, _ := newTestModule(t, "operator")
	body := `{"name":"ch","kind":"email","smtp_to":"a@b","secret":"pw"}`
	if w := do(m, http.MethodPost, "/channels", body); w.Code != http.StatusForbidden {
		t.Errorf("operator creating channel = %d, want 403", w.Code)
	}
}

func TestRBACSettingsRequiresAdmin(t *testing.T) {
	m, _ := newTestModule(t, "operator")
	if w := do(m, http.MethodPut, "/settings", `{"interval_sec":30,"silence_sec":300}`); w.Code != http.StatusForbidden {
		t.Errorf("operator updating settings = %d, want 403", w.Code)
	}
}

func TestChannelSecretNotReturnedOverHTTP(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	w := do(m, http.MethodPost, "/channels", `{"name":"ch","kind":"email","smtp_to":"a@b","secret":"super-secret-pw"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create channel = %d, body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "super-secret-pw") {
		t.Errorf("HTTP response leaked secret: %s", w.Body.String())
	}
	var ch Channel
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Secret != "" || !ch.HasSecret {
		t.Errorf("channel JSON: secret=%q has_secret=%v", ch.Secret, ch.HasSecret)
	}

	// list 同样不泄露。
	lw := do(m, http.MethodGet, "/channels", "")
	if strings.Contains(lw.Body.String(), "super-secret-pw") {
		t.Errorf("list leaked secret: %s", lw.Body.String())
	}
}

func TestCreateRuleRejectsUnknownChannel(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	w := do(m, http.MethodPost, "/rules", `{"name":"x","metric":"cpu","comparator":"gt","threshold":80,"channel_id":999}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("rule with bad channel = %d, want 400", w.Code)
	}
}

func TestCreateRuleValidationError(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	// 先建渠道,使 channel_id 有效,只剩 metric 非法。
	do(m, http.MethodPost, "/channels", `{"name":"ch","kind":"email","smtp_to":"a@b"}`)
	w := do(m, http.MethodPost, "/rules", `{"name":"x","metric":"bogus","comparator":"gt","threshold":80,"channel_id":1}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad metric = %d, want 400", w.Code)
	}
}

func TestSettingsValidationRange(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	if w := do(m, http.MethodPut, "/settings", `{"interval_sec":1,"silence_sec":300}`); w.Code != http.StatusBadRequest {
		t.Errorf("interval too small = %d, want 400", w.Code)
	}
	if w := do(m, http.MethodPut, "/settings", `{"interval_sec":30,"silence_sec":300}`); w.Code != http.StatusOK {
		t.Errorf("valid settings = %d, want 200", w.Code)
	}
}

func TestStartStopLifecycle(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	// 把间隔设短,确保 goroutine 真的循环。
	if err := m.ss.saveSettings(Settings{IntervalSec: 5, SilenceSec: 0}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Start 必须迅速返回(已在上一行验证未阻塞)。重复 Start 幂等。
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	// Stop 必须干净停止并在合理时间内返回。
	done := make(chan error, 1)
	go func() { done <- m.Stop(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s (goroutine not stopping)")
	}
	// Stop 后再 Stop 幂等。
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestMeta(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	meta := m.Meta()
	if meta.ID != "alert" || meta.Name != "监控告警" || meta.Category != "系统" {
		t.Errorf("unexpected meta: %+v", meta)
	}
	if m.HealthCheck() != nil {
		t.Error("HealthCheck should pass")
	}
	if len(m.Nav()) != 1 || m.Nav()[0].Path != "/alert" {
		t.Errorf("unexpected nav: %+v", m.Nav())
	}
}
