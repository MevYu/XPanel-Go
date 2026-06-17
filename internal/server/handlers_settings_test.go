package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/config"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// testConfigPaths 记录每个 *config.Config 对应的磁盘路径(config.path 不可从 server 包访问)。
var testConfigPaths = map[*config.Config]string{}

func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	c, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cp := &c
	testConfigPaths[cp] = path
	t.Cleanup(func() { delete(testConfigPaths, cp) })
	return cp
}

func reloadConfig(t *testing.T, c *config.Config) config.Config {
	t.Helper()
	got, err := config.Load(testConfigPaths[c])
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	return got
}

// newSettingsHandler 构造一个可直接驱动的 handler,saveCfg 走真实 c.Save()。
func newSettingsHandler(c *config.Config, banGuard *auth.IPBanGuard, probe *EntryProbeGuard, audit func(*int64, string, string, string)) *settingsHandlers {
	if audit == nil {
		audit = func(*int64, string, string, string) {}
	}
	return &settingsHandlers{
		cfg:      c,
		saveCfg:  func(cc *config.Config) error { return cc.Save() },
		banGuard: banGuard,
		probe:    probe,
		audit:    audit,
		clientIP: func(r *http.Request) string { return "1.2.3.4" },
	}
}

func withPrincipal(r *http.Request, uid int64, role string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), claimsKey, principal{uid, role}))
}

func TestSettingsGetAdmin(t *testing.T) {
	c := loadTestConfig(t)
	h := newSettingsHandler(c, nil, nil, nil)
	r := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/settings", nil), 1, "admin")
	w := httptest.NewRecorder()
	h.handleGet(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET admin code = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`"entry_path"`, `"login_max_attempts"`, `"trusted_proxies"`} {
		if !strings.Contains(body, want) {
			t.Errorf("GET body missing %s: %s", want, body)
		}
	}
	for _, leak := range []string{"jwt_secret", "db_path", c.JWTSecret} {
		if strings.Contains(body, leak) {
			t.Errorf("GET body must not leak %q", leak)
		}
	}
}

func TestSettingsGetNonAdmin(t *testing.T) {
	c := loadTestConfig(t)
	h := newSettingsHandler(c, nil, nil, nil)
	r := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/settings", nil), 2, "operator")
	w := httptest.NewRecorder()
	h.handleGet(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET non-admin code = %d, want 403", w.Code)
	}
}

func TestSettingsPutNonAdmin(t *testing.T) {
	c := loadTestConfig(t)
	h := newSettingsHandler(c, nil, nil, nil)
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"ip_ban_hours":10}`)), 2, "operator")
	w := httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("PUT non-admin code = %d, want 403", w.Code)
	}
}

func TestSettingsPutHotFields(t *testing.T) {
	c := loadTestConfig(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	banGuard, err := auth.NewIPBanGuard(st, 5, 72*time.Hour, time.Now)
	if err != nil {
		t.Fatalf("banGuard: %v", err)
	}
	var probeBanned []string
	probe := NewEntryProbeGuard(10, time.Hour, func(ip string) { probeBanned = append(probeBanned, ip) }, time.Now)

	h := newSettingsHandler(c, banGuard, probe, nil)
	body := `{"login_max_attempts":1,"ip_ban_hours":5,"entry_probe_max":2,"entry_probe_window_minutes":30}`
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body)), 1, "admin")
	w := httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT hot fields code = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"restart_required":[]`) {
		t.Errorf("hot-only change must report empty restart_required, got %s", w.Body.String())
	}

	got := reloadConfig(t, c)
	if got.LoginMaxAttempts != 1 || got.IPBanHours != 5 || got.EntryProbeMax != 2 || got.EntryProbeWindowMinutes != 30 {
		t.Fatalf("hot fields not persisted: %+v", got)
	}

	// banGuard 已热应用阈值=1:一次失败即封。
	banGuard.Fail("9.9.9.9")
	if !banGuard.Banned("9.9.9.9") {
		t.Error("banGuard threshold not hot-applied (login_max_attempts=1)")
	}
	// probe 已热应用 max=2:3 次探测触发封禁。
	probe.Probe("5.5.5.5")
	probe.Probe("5.5.5.5")
	probe.Probe("5.5.5.5")
	if len(probeBanned) != 1 || probeBanned[0] != "5.5.5.5" {
		t.Errorf("probe threshold not hot-applied (entry_probe_max=2), banned=%v", probeBanned)
	}
}

func TestSettingsPutEntryPathNoConfirm(t *testing.T) {
	c := loadTestConfig(t)
	orig := c.EntryPath
	h := newSettingsHandler(c, nil, nil, nil)
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"entry_path":"newpath123"}`)), 1, "admin")
	w := httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("entry_path change without confirm code = %d, want 428", w.Code)
	}
	got := reloadConfig(t, c)
	if got.EntryPath != orig {
		t.Errorf("entry_path must be unchanged without confirm: %q != %q", got.EntryPath, orig)
	}
}

func TestSettingsPutEntryPathWithConfirm(t *testing.T) {
	c := loadTestConfig(t)
	h := newSettingsHandler(c, nil, nil, nil)
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"entry_path":"newpath123"}`)), 1, "admin")
	r.Header.Set("X-Confirm-Danger", "yes")
	w := httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("entry_path with confirm code = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"entry_path"`) {
		t.Errorf("restart_required should contain entry_path, got %s", w.Body.String())
	}
	got := reloadConfig(t, c)
	if got.EntryPath != "/newpath123" {
		t.Errorf("entry_path persisted = %q, want /newpath123", got.EntryPath)
	}
}

func TestSettingsPutInvalidEntryPath(t *testing.T) {
	c := loadTestConfig(t)
	orig := c.EntryPath
	h := newSettingsHandler(c, nil, nil, nil)
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"entry_path":"a/b"}`)), 1, "admin")
	r.Header.Set("X-Confirm-Danger", "yes")
	w := httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid entry_path code = %d, want 400", w.Code)
	}
	got := reloadConfig(t, c)
	if got.EntryPath != orig {
		t.Errorf("invalid entry_path must persist nothing: %q != %q", got.EntryPath, orig)
	}
}

func TestSettingsPutInvalidRanges(t *testing.T) {
	c := loadTestConfig(t)
	h := newSettingsHandler(c, nil, nil, nil)
	for _, body := range []string{`{"login_max_attempts":0}`, `{"login_max_attempts":99999}`} {
		r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body)), 1, "admin")
		w := httptest.NewRecorder()
		h.handlePut(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s code = %d, want 400", body, w.Code)
		}
	}
}

func TestSettingsPutInvalidTrustedProxies(t *testing.T) {
	c := loadTestConfig(t)
	h := newSettingsHandler(c, nil, nil, nil)
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"trusted_proxies":["not-an-ip"]}`)), 1, "admin")
	w := httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid trusted_proxies code = %d, want 400", w.Code)
	}
}

func TestSettingsPutAddr(t *testing.T) {
	c := loadTestConfig(t)
	h := newSettingsHandler(c, nil, nil, nil)

	// 无确认头 -> 428。
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"addr":"0.0.0.0:9000"}`)), 1, "admin")
	w := httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("addr change without confirm code = %d, want 428", w.Code)
	}

	// 带确认头 -> 200 + persisted + restart_required 含 addr。
	r = withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"addr":"0.0.0.0:9000"}`)), 1, "admin")
	r.Header.Set("X-Confirm-Danger", "yes")
	w = httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("addr with confirm code = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"addr"`) {
		t.Errorf("restart_required should contain addr, got %s", w.Body.String())
	}
	if got := reloadConfig(t, c); got.Addr != "0.0.0.0:9000" {
		t.Errorf("addr persisted = %q, want 0.0.0.0:9000", got.Addr)
	}
}

func TestSettingsPutTrustedProxies(t *testing.T) {
	c := loadTestConfig(t)
	h := newSettingsHandler(c, nil, nil, nil)
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"trusted_proxies":["10.0.0.0/8"]}`)), 1, "admin")
	w := httptest.NewRecorder()
	h.handlePut(w, r) // 无需确认头
	if w.Code != http.StatusOK {
		t.Fatalf("trusted_proxies change code = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"trusted_proxies"`) {
		t.Errorf("restart_required should contain trusted_proxies, got %s", w.Body.String())
	}
	got := reloadConfig(t, c)
	if len(got.TrustedProxies) != 1 || got.TrustedProxies[0] != "10.0.0.0/8" {
		t.Errorf("trusted_proxies persisted = %v", got.TrustedProxies)
	}
}

func TestSettingsPutAuditNoValueLeak(t *testing.T) {
	c := loadTestConfig(t)
	var gotAction, gotDetail string
	audit := func(_ *int64, action, detail, _ string) {
		gotAction, gotDetail = action, detail
	}
	h := newSettingsHandler(c, nil, nil, audit)
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"entry_path":"newpath123"}`)), 1, "admin")
	r.Header.Set("X-Confirm-Danger", "yes")
	w := httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	if gotAction != "panel.settings.update" {
		t.Errorf("audit action = %q, want panel.settings.update", gotAction)
	}
	if !strings.Contains(gotDetail, "entry_path") {
		t.Errorf("audit detail should name entry_path, got %q", gotDetail)
	}
	if strings.Contains(gotDetail, "newpath123") {
		t.Errorf("audit detail must NOT contain the value, got %q", gotDetail)
	}
}

func TestSettingsPutUnknownField(t *testing.T) {
	c := loadTestConfig(t)
	h := newSettingsHandler(c, nil, nil, nil)
	r := withPrincipal(httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"bogus":1}`)), 1, "admin")
	w := httptest.NewRecorder()
	h.handlePut(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field code = %d, want 400", w.Code)
	}
}
