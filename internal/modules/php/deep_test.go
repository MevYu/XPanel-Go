package php

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- raw ini validation ---

func TestValidateRawIni(t *testing.T) {
	if err := validateRawIni("[PHP]\nmemory_limit = 256M\n"); err != nil {
		t.Errorf("valid raw ini rejected: %v", err)
	}
	if err := validateRawIni("x\x00y"); err == nil {
		t.Error("NUL byte must be rejected")
	}
	if err := validateRawIni(strings.Repeat("a", maxRawIni+1)); err == nil {
		t.Error("oversized content must be rejected")
	}
}

// --- disable_functions ---

func TestParseDisableFunctions(t *testing.T) {
	ini := "[PHP]\ndisable_functions = exec, system ,passthru\nmemory_limit = 128M\n"
	got := parseDisableFunctions(ini)
	want := []string{"exec", "passthru", "system"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("parseDisableFunctions = %v, want %v", got, want)
	}
	if len(parseDisableFunctions("memory_limit = 128M")) != 0 {
		t.Error("absent disable_functions must yield empty list")
	}
}

func TestValidateDisableFunctions(t *testing.T) {
	if err := validateDisableFunctions([]string{"exec", "system"}); err != nil {
		t.Errorf("known dangerous funcs rejected: %v", err)
	}
	if err := validateDisableFunctions([]string{"my_app_func"}); err == nil {
		t.Error("non-whitelisted function must be rejected")
	}
	// 防注入:含逗号/换行的伪函数名既不在白名单,也被拒。
	if err := validateDisableFunctions([]string{"exec\nauto_prepend_file=x"}); err == nil {
		t.Error("injection-shaped name must be rejected")
	}
}

func TestApplyDisableFunctionsInPlace(t *testing.T) {
	ini := "[PHP]\ndisable_functions = exec\nmemory_limit = 128M\n"
	out := applyDisableFunctions(ini, []string{"system", "exec", "system"})
	if got := parseDisableFunctions(out); strings.Join(got, ",") != "exec,system" {
		t.Errorf("disable_functions = %v, want [exec system] deduped", got)
	}
	if strings.Count(out, "disable_functions") != 1 {
		t.Errorf("disable_functions duplicated: %s", out)
	}
	if !strings.Contains(out, "memory_limit = 128M") {
		t.Error("unrelated lines must be preserved")
	}
}

func TestApplyDisableFunctionsAppendsWhenMissing(t *testing.T) {
	out := applyDisableFunctions("memory_limit = 128M", []string{"exec"})
	if parseDisableFunctions(out)[0] != "exec" {
		t.Errorf("disable_functions not appended: %s", out)
	}
}

// --- fpm config ---

func TestValidateFpmChanges(t *testing.T) {
	ok := map[string]string{
		"pm": "dynamic", "pm.max_children": "50", "request_terminate_timeout": "100s",
		"request_slowlog_timeout": "0",
	}
	if err := validateFpmChanges(ok); err != nil {
		t.Errorf("valid fpm changes rejected: %v", err)
	}
	bad := []map[string]string{
		{"pm": "weird"},                      // 非法 pm 模式
		{"pm.max_children": "-1"},            // 负数
		{"pm.max_children": "50M"},           // 非整数
		{"request_terminate_timeout": "abc"}, // 非时长
		{"pm.max_children": "5\n0"},          // 注入字符
		{"php_admin_value": "x"},             // 非白名单 key(危险:可改 disable_functions)
	}
	for i, c := range bad {
		if err := validateFpmChanges(c); err == nil {
			t.Errorf("case %d: expected rejection for %v", i, c)
		}
	}
}

func TestApplyFpmChanges(t *testing.T) {
	conf := "[www]\npm = dynamic\npm.max_children = 5\n"
	out := applyFpmChanges(conf, map[string]string{"pm": "static", "pm.max_children": "20"})
	got := parseFpmConfig(out)
	if got["pm"] != "static" || got["pm.max_children"] != "20" {
		t.Errorf("fpm config = %v, want pm=static max_children=20", got)
	}
	if strings.Count(out, "pm.max_children") != 1 {
		t.Errorf("pm.max_children duplicated: %s", out)
	}
}

// --- log tail ---

func TestTailLines(t *testing.T) {
	in := "l1\nl2\nl3\nl4\n"
	if got := tailLines(in, 2); got != "l3\nl4" {
		t.Errorf("tailLines(2) = %q, want l3\\nl4", got)
	}
	if got := tailLines(in, 10); got != "l1\nl2\nl3\nl4" {
		t.Errorf("tailLines(10) = %q", got)
	}
	if got := tailLines(in, 0); got != "" {
		t.Errorf("tailLines(0) = %q, want empty", got)
	}
}

func TestReadLogTailMissing(t *testing.T) {
	if _, ok := readLogTail("/nonexistent/php/slow.log", 10); ok {
		t.Error("missing log must return ok=false")
	}
}

// --- HTTP: schema endpoints ---

func TestIniSchemaEndpoint(t *testing.T) {
	_, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/ini/schema", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "memory_limit") {
		t.Fatalf("ini schema = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestFpmSchemaEndpoint(t *testing.T) {
	_, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/fpm/schema", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pm.max_children") {
		t.Fatalf("fpm schema = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDangerFuncCandidatesEndpoint(t *testing.T) {
	_, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/disabled-functions/candidates", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "shell_exec") {
		t.Fatalf("danger candidates = %d body=%s", rec.Code, rec.Body.String())
	}
}

// --- HTTP: raw ini ---

func TestGetRawIniReturnsFullContent(t *testing.T) {
	m, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions/8.1/ini/raw", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "[Date]") {
		t.Fatalf("raw ini = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPutRawIniAdminWrites(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	base := setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/ini/raw", strings.NewReader("[PHP]\nmemory_limit = 999M\n"))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put raw ini = %d body=%s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("must audit once, got %d", *audited)
	}
	content, _ := os.ReadFile(filepath.Join(base, "8.1", "etc", "php.ini"))
	if !strings.Contains(string(content), "memory_limit = 999M") {
		t.Errorf("raw ini not written: %s", content)
	}
}

func TestPutRawIniRejectsNUL(t *testing.T) {
	m, _, r := newTestModule(t, "admin", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/ini/raw", strings.NewReader("a\x00b"))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("raw ini with NUL = %d, want 400", rec.Code)
	}
}

func TestPutRawIniRequiresConfirm(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("PUT", "/versions/8.1/ini/raw", strings.NewReader("[PHP]\n")))
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("raw ini without confirm = %d, want 428", rec.Code)
	}
	if *audited != 0 {
		t.Error("unconfirmed raw ini must not audit")
	}
}

// --- HTTP: disable_functions ---

func TestGetDisabledReadsIni(t *testing.T) {
	m, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	base := setupInstall(t, m)
	ini := filepath.Join(base, "8.1", "etc", "php.ini")
	os.WriteFile(ini, []byte("[PHP]\ndisable_functions = exec,system\n"), 0o644)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions/8.1/disabled-functions", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "system") {
		t.Fatalf("get disabled = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPutDisabledAdminWrites(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	base := setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/disabled-functions", strings.NewReader(`["exec","shell_exec"]`))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put disabled = %d body=%s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("must audit once, got %d", *audited)
	}
	content, _ := os.ReadFile(filepath.Join(base, "8.1", "etc", "php.ini"))
	if !strings.Contains(string(content), "disable_functions = exec,shell_exec") {
		t.Errorf("disable_functions not written: %s", content)
	}
}

func TestPutDisabledRejectsUnknownFunc(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/disabled-functions", strings.NewReader(`["my_func"]`))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown func = %d, want 400", rec.Code)
	}
	if *audited != 0 {
		t.Error("rejected change must not audit")
	}
}

func TestPutDisabledReadonlyForbidden(t *testing.T) {
	m, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/disabled-functions", strings.NewReader(`["exec"]`))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly put disabled = %d, want 403", rec.Code)
	}
}

// --- HTTP: fpm config ---

func setupFpmPool(t *testing.T, base string) {
	t.Helper()
	dir := filepath.Join(base, "8.1", "etc", "php-fpm.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "[www]\npm = dynamic\npm.max_children = 5\n"
	if err := os.WriteFile(filepath.Join(dir, "www.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGetFpmConfig(t *testing.T) {
	m, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	base := setupInstall(t, m)
	setupFpmPool(t, base)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions/8.1/fpm/config", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pm.max_children") {
		t.Fatalf("get fpm config = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPutFpmConfigAdminWrites(t *testing.T) {
	m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
	base := setupInstall(t, m)
	setupFpmPool(t, base)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/fpm/config", strings.NewReader(`{"pm":"static","pm.max_children":"30"}`))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put fpm config = %d body=%s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("must audit once, got %d", *audited)
	}
	content, _ := os.ReadFile(filepath.Join(base, "8.1", "etc", "php-fpm.d", "www.conf"))
	if !strings.Contains(string(content), "pm.max_children = 30") {
		t.Errorf("fpm config not written: %s", content)
	}
}

func TestPutFpmConfigRejectsBadValue(t *testing.T) {
	m, _, r := newTestModule(t, "admin", &mockRunner{}, nil)
	base := setupInstall(t, m)
	setupFpmPool(t, base)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.1/fpm/config", strings.NewReader(`{"pm.max_children":"notanumber"}`))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad fpm value = %d, want 400", rec.Code)
	}
}

func TestFpmStatusEndpoint(t *testing.T) {
	mr := &mockRunner{activeUnits: map[string]bool{"php-fpm-8.1": true}}
	m, _, r := newTestModule(t, "readonly", mr, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions/8.1/fpm/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("fpm status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"active":true`) {
		t.Errorf("fpm status missing active: %s", rec.Body.String())
	}
}

// --- HTTP: logs ---

func TestLogTailEndpoint(t *testing.T) {
	m, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	base := setupInstall(t, m)
	logDir := filepath.Join(base, "8.1", "var", "log")
	os.MkdirAll(logDir, 0o755)
	os.WriteFile(filepath.Join(logDir, "slow.log"), []byte("line1\nline2\nline3\n"), 0o644)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions/8.1/log/slow?lines=2", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("log tail = %d", rec.Code)
	}
	if rec.Body.String() != "line2\nline3" {
		t.Errorf("log tail = %q, want line2\\nline3", rec.Body.String())
	}
}

func TestLogTailMissingFile(t *testing.T) {
	m, _, r := newTestModule(t, "readonly", &mockRunner{}, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions/8.1/log/error", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing log = %d, want 404", rec.Code)
	}
}

// --- HTTP: cli + version enrichment ---

func TestCLIVersionEndpoint(t *testing.T) {
	mr := &mockRunner{cliBanner: "PHP 8.1.0 (cli) (built: ...)"}
	_, _, r := newTestModule(t, "readonly", mr, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/cli", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"available":true`) {
		t.Fatalf("cli = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestListVersionsEnrichesFpmAndCLI(t *testing.T) {
	mr := &mockRunner{
		cliBanner:   "PHP 8.1.0 (cli)", // 与 Version() 返回一致 -> CLIDefault
		activeUnits: map[string]bool{"php-fpm-8.1": true},
	}
	m, _, r := newTestModule(t, "readonly", mr, nil)
	setupInstall(t, m)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `"fpm_active":true`) {
		t.Errorf("versions missing fpm_active: %s", body)
	}
	if !strings.Contains(body, `"cli_default":true`) {
		t.Errorf("versions missing cli_default: %s", body)
	}
	if !strings.Contains(body, `"fpm_unit":"php-fpm-8.1"`) {
		t.Errorf("versions missing fpm_unit: %s", body)
	}
}
