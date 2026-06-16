package php

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// writeFile 在 path 处建父目录并写内容。
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// setupDebianTree 在 root 下铺一个 Ubuntu php8.3-fpm 风格布局,返回 root、binDir。
func setupDebianTree(t *testing.T) (root, binDir string) {
	t.Helper()
	root = t.TempDir()
	binDir = t.TempDir()
	writeFile(t, filepath.Join(root, "8.3", "fpm", "php.ini"), "[PHP]\nmemory_limit = 256M\n")
	writeFile(t, filepath.Join(root, "8.3", "fpm", "pool.d", "www.conf"), "[www]\npm = dynamic\n")
	// CLI-only 安装(无 fpm 子目录)仍是一个版本,但不标 HasFpm。
	writeFile(t, filepath.Join(root, "8.1", "cli", "php.ini"), "[PHP]\n")
	// 非版本目录与文件须被忽略。
	if err := os.MkdirAll(filepath.Join(root, "notaversion"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "9.9"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(binDir, "php8.3"), "#!/bin/sh\n")
	return root, binDir
}

func TestDetectDebianInstallsParsesLayout(t *testing.T) {
	root, binDir := setupDebianTree(t)
	got := detectDebianInstalls(root, binDir)

	var v83 *debianInstall
	for i := range got {
		if got[i].Version == "8.3" {
			v83 = &got[i]
		}
	}
	if v83 == nil {
		t.Fatalf("8.3 not detected, got %+v", got)
	}
	if want := filepath.Join(root, "8.3", "fpm", "php.ini"); v83.IniPath != want {
		t.Errorf("IniPath = %q, want %q", v83.IniPath, want)
	}
	if want := filepath.Join(root, "8.3", "fpm", "pool.d", "www.conf"); v83.PoolConf != want {
		t.Errorf("PoolConf = %q, want %q", v83.PoolConf, want)
	}
	if v83.FpmUnit != "php8.3-fpm" {
		t.Errorf("FpmUnit = %q, want php8.3-fpm", v83.FpmUnit)
	}
	if want := filepath.Join(binDir, "php8.3"); v83.PhpBin != want {
		t.Errorf("PhpBin = %q, want %q", v83.PhpBin, want)
	}
	if !v83.HasFpm {
		t.Error("8.3 should be marked HasFpm")
	}
}

func TestDetectDebianInstallsCLIOnlyNoFpm(t *testing.T) {
	root, binDir := setupDebianTree(t)
	got := detectDebianInstalls(root, binDir)
	for _, in := range got {
		if in.Version == "8.1" {
			if in.HasFpm {
				t.Error("8.1 has no fpm/ subdir, must not be HasFpm")
			}
			if in.FpmUnit != "php8.1-fpm" {
				t.Errorf("FpmUnit = %q, want php8.1-fpm", in.FpmUnit)
			}
			return
		}
	}
	t.Errorf("8.1 (cli-only) not detected, got %+v", got)
}

func TestDetectDebianInstallsMissingRoot(t *testing.T) {
	if got := detectDebianInstalls("/nonexistent/etc/php", "/usr/bin"); got != nil {
		t.Errorf("missing root must yield nil, got %v", got)
	}
}

func TestProbeFpmActiveFromProc(t *testing.T) {
	proc := t.TempDir()
	writeFile(t, filepath.Join(proc, "123", "comm"), "php-fpm8.3\n")
	writeFile(t, filepath.Join(proc, "456", "comm"), "bash\n")

	if !probeFpmActiveProc("php8.3-fpm", proc) {
		t.Error("php8.3-fpm should be detected active via /proc")
	}
	if probeFpmActiveProc("php8.2-fpm", proc) {
		t.Error("php8.2-fpm must not be detected (no matching process)")
	}
	if probeFpmActiveProc("not-a-unit", proc) {
		t.Error("malformed unit must not match")
	}
}

// setupDebianModule 返回一个 module,其 settings 指向空 aaPanel base + 注入的 Debian root/binDir。
func setupDebianModule(t *testing.T, run PHPRunner) (*Module, *chi.Mux, string, string) {
	t.Helper()
	m, _, r := newTestModule(t, "admin", run, nil)
	base := t.TempDir() // 空 aaPanel base:无 aaPanel 安装
	root, binDir := setupDebianTree(t)
	set := DefaultSettings()
	set.InstallBase = base
	set.FpmConfDir = base
	set.DebianRoot = root
	set.DebianBinDir = binDir
	set.ProcRoot = t.TempDir()
	if err := m.ps.setSettings(set); err != nil {
		t.Fatal(err)
	}
	return m, r, root, binDir
}

// --- HTTP: /versions 并入 Debian 安装,标 source=debian ---

func TestListVersionsIncludesDebianInstalls(t *testing.T) {
	m, r, root, _ := setupDebianModule(t, &mockRunner{})
	_ = m
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /versions = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"version":"8.3"`) {
		t.Errorf("8.3 missing from /versions: %s", body)
	}
	if !strings.Contains(body, `"source":"debian"`) {
		t.Errorf("debian source missing: %s", body)
	}
	if !strings.Contains(body, filepath.Join(root, "8.3", "fpm", "php.ini")) {
		t.Errorf("debian ini_path missing: %s", body)
	}
	if !strings.Contains(body, `"fpm_unit":"php8.3-fpm"`) {
		t.Errorf("debian fpm_unit missing: %s", body)
	}
}

// aaPanel 与 Debian 同版本号时,aaPanel 优先(不被 debian 覆盖)。
func TestListVersionsAapanelWinsOnConflict(t *testing.T) {
	m, _, r := newTestModule(t, "admin", &mockRunner{}, nil)
	base := t.TempDir()
	root, binDir := t.TempDir(), t.TempDir()
	// aaPanel 8.3 安装
	writeFile(t, filepath.Join(base, "8.3", "etc", "php.ini"), sampleIni)
	// Debian 也有 8.3
	writeFile(t, filepath.Join(root, "8.3", "fpm", "php.ini"), "[PHP]\n")
	set := DefaultSettings()
	set.InstallBase = base
	set.FpmConfDir = base
	set.DebianRoot = root
	set.DebianBinDir = binDir
	if err := m.ps.setSettings(set); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions", nil))
	body := rec.Body.String()
	if strings.Contains(body, `"source":"debian"`) {
		t.Errorf("conflicting 8.3 must resolve to aapanel only, got: %s", body)
	}
	if !strings.Contains(body, `"source":"aapanel"`) {
		t.Errorf("aapanel 8.3 missing: %s", body)
	}
	// 只应有一条 8.3。
	if n := strings.Count(body, `"version":"8.3"`); n != 1 {
		t.Errorf("8.3 should appear once, got %d: %s", n, body)
	}
}

// --- ini handler 对 debian 版本走 /etc/php/<ver>/fpm/php.ini ---

func TestGetIniDebianReadsFpmPath(t *testing.T) {
	m, r, root, _ := setupDebianModule(t, &mockRunner{})
	_ = m
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions/8.3/ini", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET debian ini = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "memory_limit") {
		t.Errorf("debian ini view missing memory_limit: %s", rec.Body.String())
	}
	_ = root
}

func TestPutIniDebianWritesFpmPath(t *testing.T) {
	m, r, root, _ := setupDebianModule(t, &mockRunner{})
	_ = m
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.3/ini", strings.NewReader(`{"memory_limit":"512M"}`))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT debian ini = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	content, _ := os.ReadFile(filepath.Join(root, "8.3", "fpm", "php.ini"))
	if !strings.Contains(string(content), "memory_limit = 512M") {
		t.Errorf("debian /etc/php/8.3/fpm/php.ini not updated:\n%s", content)
	}
}

// 未安装的版本(两布局都无)→ 404,且不触达文件。
func TestGetIniUnknownVersion404(t *testing.T) {
	m, r, _, _ := setupDebianModule(t, &mockRunner{})
	_ = m
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions/5.6/ini", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown version ini = %d, want 404", rec.Code)
	}
}

// --- fpm config handler 对 debian 版本走 pool.d/www.conf ---

func TestGetFpmDebianReadsPoolConf(t *testing.T) {
	m, r, _, _ := setupDebianModule(t, &mockRunner{})
	_ = m
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions/8.3/fpm/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET debian fpm config = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "dynamic") {
		t.Errorf("debian pool conf not read: %s", rec.Body.String())
	}
}

func TestPutFpmDebianWritesPoolConf(t *testing.T) {
	m, r, root, _ := setupDebianModule(t, &mockRunner{})
	_ = m
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/versions/8.3/fpm/config", strings.NewReader(`{"pm.max_children":"50"}`))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT debian fpm = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	content, _ := os.ReadFile(filepath.Join(root, "8.3", "fpm", "pool.d", "www.conf"))
	if !strings.Contains(string(content), "pm.max_children = 50") {
		t.Errorf("debian pool.d/www.conf not updated:\n%s", content)
	}
}

// --- log handler 对 debian 版本走 /var/log/php<ver>-fpm.log ---

func TestLogDebianResolvesVarLogPath(t *testing.T) {
	m, r, _, _ := setupDebianModule(t, &mockRunner{})
	p, ok := func() (versionPaths, bool) {
		set, _ := m.ps.getSettings()
		return set.resolveVersion("8.3")
	}()
	if !ok {
		t.Fatal("8.3 must resolve")
	}
	if p.Source != sourceDebian {
		t.Errorf("source = %q, want debian", p.Source)
	}
	if p.ErrorLog != "/var/log/php8.3-fpm.log" {
		t.Errorf("ErrorLog = %q, want /var/log/php8.3-fpm.log", p.ErrorLog)
	}
	if p.SlowLog != "/var/log/php8.3-fpm.slow.log" {
		t.Errorf("SlowLog = %q, want /var/log/php8.3-fpm.slow.log", p.SlowLog)
	}
	_ = r
}

// --- fpm_active 无 systemd 时退化为 procfs 扫描 ---

func TestListVersionsFpmActiveViaProcFallback(t *testing.T) {
	// runner.Available 报错 = 无 systemd,触发 procfs 退化。
	m, _, r := newTestModule(t, "admin", &mockRunner{available: errNoSystemd}, nil)
	base := t.TempDir()
	root, binDir := setupDebianTree(t)
	proc := t.TempDir()
	writeFile(t, filepath.Join(proc, "100", "comm"), "php-fpm8.3\n")
	set := DefaultSettings()
	set.InstallBase = base
	set.FpmConfDir = base
	set.DebianRoot = root
	set.DebianBinDir = binDir
	set.ProcRoot = proc
	if err := m.ps.setSettings(set); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/versions", nil))
	body := rec.Body.String()
	// 8.3 在 procfs 有进程 → fpm_active true;8.1 无 → false。
	if !strings.Contains(body, `"version":"8.3"`) {
		t.Fatalf("8.3 missing: %s", body)
	}
	idx := strings.Index(body, `"version":"8.3"`)
	if idx < 0 || !strings.Contains(body[idx:], `"fpm_active":true`) {
		t.Errorf("8.3 fpm_active should be true via procfs: %s", body)
	}
}

var errNoSystemd = errorString("no systemd")

type errorString string

func (e errorString) Error() string { return string(e) }
