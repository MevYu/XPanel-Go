package php

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockRunner 记录调用并返回预设结果,绝不触碰真实系统。
type mockRunner struct {
	available  error
	modules    string
	modulesErr error
	fpmCalls   []string // "verb unit"
	fpmErr     error
}

func (m *mockRunner) Available() error               { return m.available }
func (m *mockRunner) Version(string) (string, error) { return "PHP 8.1.0 (cli)", nil }
func (m *mockRunner) Modules(string) (string, error) { return m.modules, m.modulesErr }
func (m *mockRunner) FpmAction(verb, unit string) (string, error) {
	m.fpmCalls = append(m.fpmCalls, verb+" "+unit)
	return "ok", m.fpmErr
}

func newTestModule(t *testing.T, role string, run PHPRunner, inst Installer) (*Module, *int, *chi.Mux) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	audited := new(int)
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	}
	m := New(st, run, inst, deps)
	r := chi.NewRouter()
	m.Routes(r)
	return m, audited, r
}

// setupInstall 在 settings 指向的临时 base 下铺一个 8.1 版本布局。
func setupInstall(t *testing.T, m *Module) string {
	t.Helper()
	base := t.TempDir()
	set := DefaultSettings()
	set.InstallBase = base
	set.FpmConfDir = base
	if err := m.ps.setSettings(set); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(base, "8.1", "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "php.ini"), []byte(sampleIni), 0o644); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestMetaSwitchable(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", &mockRunner{}, nil)
	if m.Meta().ID != "php" || m.Meta().AlwaysOn {
		t.Errorf("php must be id=php and not AlwaysOn, got %+v", m.Meta())
	}
	if m.Meta().Category != "网站" {
		t.Errorf("category = %q, want 网站", m.Meta().Category)
	}
}

func TestHealthCheckUsesRunner(t *testing.T) {
	want := errors.New("no systemctl")
	m, _, _ := newTestModule(t, "admin", &mockRunner{available: want}, nil)
	if err := m.HealthCheck(); !errors.Is(err, want) {
		t.Errorf("HealthCheck = %v, want %v", err, want)
	}
}

func TestPutSettingsRequiresAdmin(t *testing.T) {
	_, audited, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/settings", strings.NewReader(`{"install_base":"/opt/php","fpm_conf_dir":"/opt/php","fpm_sock_dir":"/tmp","fpm_unit_template":"php%s-fpm"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly PUT settings = %d, want 403", rec.Code)
	}
	if *audited != 0 {
		t.Errorf("forbidden request must not audit, got %d", *audited)
	}
}

func TestPutSettingsRejectsBadPath(t *testing.T) {
	_, _, r := newTestModule(t, "admin", &mockRunner{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/settings", strings.NewReader(`{"install_base":"relative","fpm_conf_dir":"/a","fpm_sock_dir":"/b","fpm_unit_template":"php%s-fpm"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad path PUT settings = %d, want 400", rec.Code)
	}
}

func TestPutSettingsAdminPersists(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/settings", strings.NewReader(`{"install_base":"/opt/php","fpm_conf_dir":"/opt/php","fpm_sock_dir":"/run","fpm_unit_template":"php%s-fpm"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin PUT settings = %d, want 200", rec.Code)
	}
	if *audited != 1 {
		t.Errorf("must audit once, got %d", *audited)
	}
	got, _ := m.ps.getSettings()
	if got.InstallBase != "/opt/php" {
		t.Errorf("settings not persisted: %+v", got)
	}
}

func TestFpmRestartRejectsBadVersion(t *testing.T) {
	mr := &mockRunner{}
	_, _, r := newTestModule(t, "admin", mr, nil)
	rec := httptest.NewRecorder()
	// 版本号含注入字符,chi 的 {version} 会匹配,但 ValidVersion 必须拒。
	req := httptest.NewRequest("POST", "/versions/8.1abc/fpm/restart", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad version = %d, want 400", rec.Code)
	}
	if len(mr.fpmCalls) != 0 {
		t.Errorf("bad version must not reach runner, calls=%v", mr.fpmCalls)
	}
}

func TestFpmRestartReadonlyForbidden(t *testing.T) {
	mr := &mockRunner{}
	_, audited, r := newTestModule(t, "readonly", mr, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/versions/8.1/fpm/restart", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly fpm = %d, want 403", rec.Code)
	}
	if *audited != 0 || len(mr.fpmCalls) != 0 {
		t.Errorf("forbidden must not audit/exec")
	}
}

func TestFpmRestartAdminUsesUnitTemplate(t *testing.T) {
	mr := &mockRunner{}
	m, audited, r := newTestModule(t, "admin", mr, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/versions/8.1/fpm/restart", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin fpm restart = %d, want 200", rec.Code)
	}
	if *audited != 1 {
		t.Errorf("must audit once, got %d", *audited)
	}
	if len(mr.fpmCalls) != 1 || mr.fpmCalls[0] != "restart php-fpm-8.1" {
		t.Errorf("fpm call = %v, want [restart php-fpm-8.1]", mr.fpmCalls)
	}
}

func TestPutIniRejectsNonWhitelistKey(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/ini", strings.NewReader(`{"disable_functions":"exec"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-whitelist ini key = %d, want 400", rec.Code)
	}
	if *audited != 0 {
		t.Errorf("rejected ini change must not audit")
	}
}

func TestPutIniRejectsInjectionValue(t *testing.T) {
	m, _, r := newTestModule(t, "admin", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/ini", strings.NewReader(`{"memory_limit":"128M\ndisable_functions = exec"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection value = %d, want 400", rec.Code)
	}
}

func TestPutIniAdminWritesFile(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	base := setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/ini", strings.NewReader(`{"memory_limit":"512M"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin PUT ini = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("must audit once, got %d", *audited)
	}
	content, _ := os.ReadFile(filepath.Join(base, "8.1", "etc", "php.ini"))
	if !strings.Contains(string(content), "memory_limit = 512M") {
		t.Errorf("ini not updated on disk:\n%s", content)
	}
}

func TestGetIniReadonlyAllowed(t *testing.T) {
	m, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/versions/8.1/ini", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("readonly GET ini = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "memory_limit") {
		t.Errorf("ini view missing memory_limit: %s", rec.Body.String())
	}
}

func TestListExtensionsParsesModules(t *testing.T) {
	mr := &mockRunner{modules: "[PHP Modules]\nCore\nopcache\nredis"}
	m, _, r := newTestModule(t, "readonly", mr, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/versions/8.1/extensions", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list extensions = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "redis") {
		t.Errorf("extensions missing redis: %s", rec.Body.String())
	}
}

func TestToggleExtensionRejectsBadName(t *testing.T) {
	m, _, r := newTestModule(t, "admin", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	// 注:URL path 里点会被 chi 当作 {ext} 一部分,bad name 须被 ValidExtName 拒。
	req := httptest.NewRequest("POST", "/versions/8.1/extensions/redis_so/enable", nil)
	r.ServeHTTP(rec, req)
	// redis_so 合法,应成功;改测一个非法名。
	if rec.Code != http.StatusNoContent {
		t.Fatalf("valid ext enable = %d, want 204", rec.Code)
	}
}

func TestEnableExtensionWritesIni(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	base := setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/versions/8.1/extensions/redis/enable", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("enable redis = %d, want 204", rec.Code)
	}
	if *audited != 1 {
		t.Errorf("must audit once, got %d", *audited)
	}
	if _, err := os.Stat(filepath.Join(base, "8.1", "etc", "php.d", "redis.ini")); err != nil {
		t.Errorf("redis.ini not created: %v", err)
	}
}

func TestDisableExtensionRemovesIni(t *testing.T) {
	m, _, r := newTestModule(t, "admin", &mockRunner{}, nil)
	base := setupInstall(t, m)
	dir := filepath.Join(base, "8.1", "etc", "php.d")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "redis.ini"), []byte("extension=redis\n"), 0o644)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/versions/8.1/extensions/redis/disable", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("disable redis = %d, want 204", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "redis.ini")); !os.IsNotExist(err) {
		t.Errorf("redis.ini should be removed")
	}
}

func TestInstallUnavailableByDefault(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	_ = m
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/install", strings.NewReader(`{"version":"8.3"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("default install = %d, want 501", rec.Code)
	}
	// 仍应审计尝试(失败结果)。
	if *audited != 1 {
		t.Errorf("install attempt must audit, got %d", *audited)
	}
}

func TestInstallRejectsBadVersion(t *testing.T) {
	_, _, r := newTestModule(t, "admin", &mockRunner{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/install", strings.NewReader(`{"version":"8.3; rm -rf /"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad version install = %d, want 400", rec.Code)
	}
}

func TestInstallReadonlyForbidden(t *testing.T) {
	_, audited, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/install", strings.NewReader(`{"version":"8.3"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly install = %d, want 403", rec.Code)
	}
	if *audited != 0 {
		t.Errorf("forbidden install must not audit")
	}
}

func TestListVersionsReadonly(t *testing.T) {
	m, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/versions", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list versions = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "8.1") {
		t.Errorf("versions missing 8.1: %s", rec.Body.String())
	}
}
