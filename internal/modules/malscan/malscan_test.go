package malscan

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// testMod 建一个挂好路由的模块,scan_dir 指向临时目录,principal 返回给定角色。
func testMod(t *testing.T, role string) (*Module, http.Handler, string, *[]string) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	scanDir := t.TempDir()
	quarDir := filepath.Join(t.TempDir(), "quar")

	var audits []string
	m := New(st, Deps{
		Principal: func(*http.Request) (int64, string) { return 7, role },
		Audit: func(_ *int64, action, detail, _ string) {
			audits = append(audits, action+":"+detail)
		},
	})
	// 把设置指向测试目录。
	if err := m.ms.putSettings(Settings{
		ScanDir: scanDir, QuarantineDir: quarDir,
		MaxFileSize: 1 << 20, MaxFiles: 1000, ScoreToFlag: 10,
	}); err != nil {
		t.Fatalf("put settings: %v", err)
	}
	r := chi.NewRouter()
	m.Routes(r)
	return m, r, scanDir, &audits
}

func req(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func seedShell(t *testing.T, dir, name string) {
	t.Helper()
	writeSample(t, dir, name, "<?php @eval($_POST['cmd']); ?>")
}

func TestScanRequiresOperator(t *testing.T) {
	_, h, _, _ := testMod(t, "viewer")
	rec := req(t, h, http.MethodPost, "/scan", `{}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer scan: want 403, got %d", rec.Code)
	}
}

func TestScanFindsAndRecordsHits(t *testing.T) {
	m, h, dir, audits := testMod(t, "operator")
	seedShell(t, dir, "evil.php")

	rec := req(t, h, http.MethodPost, "/scan", `{}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var task Task
	_ = json.Unmarshal(rec.Body.Bytes(), &task)
	if task.Status != "done" || task.FlaggedCount != 1 {
		t.Fatalf("unexpected task: %+v", task)
	}
	hits, err := m.ms.listHits(task.ID)
	if err != nil || len(hits) == 0 {
		t.Fatalf("hits not recorded: %v %+v", err, hits)
	}
	var hasScan bool
	for _, a := range *audits {
		if len(a) >= 12 && a[:12] == "malscan.scan" {
			hasScan = true
		}
	}
	if !hasScan {
		t.Errorf("scan must be audited: %v", *audits)
	}
}

// SafeJoin 把 ".." 钳制回 root 内(中和而非报错),扫描根因此绝不逃出 scan_dir。
func TestScanContainsPathTraversal(t *testing.T) {
	_, h, dir, _ := testMod(t, "operator")
	rec := req(t, h, http.MethodPost, "/scan", `{"dir":"../../etc"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("traversal scan: want 200 (clamped), got %d (%s)", rec.Code, rec.Body)
	}
	var task Task
	_ = json.Unmarshal(rec.Body.Bytes(), &task)
	if !strings.HasPrefix(task.Root, dir) {
		t.Errorf("scan root must stay within scan_dir, got %q (scan_dir=%q)", task.Root, dir)
	}
}

// 软链逃逸:scan_dir 内的软链指向外部目录,SafeJoin 必须拒绝。
func TestScanRejectsSymlinkEscape(t *testing.T) {
	_, h, dir, _ := testMod(t, "operator")
	outside := t.TempDir()
	link := filepath.Join(dir, "evil_link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	rec := req(t, h, http.MethodPost, "/scan", `{"dir":"evil_link"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("symlink-escape scan dir: want 400, got %d (%s)", rec.Code, rec.Body)
	}
}

func TestQuarantineRequiresConfirm(t *testing.T) {
	_, h, dir, _ := testMod(t, "admin")
	seedShell(t, dir, "evil.php")
	rec := req(t, h, http.MethodPost, "/quarantine", `{"path":"evil.php"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("quarantine w/o confirm: want 428, got %d", rec.Code)
	}
}

func TestQuarantineRequiresAdmin(t *testing.T) {
	_, h, dir, _ := testMod(t, "operator")
	seedShell(t, dir, "evil.php")
	rec := req(t, h, http.MethodPost, "/quarantine", `{"path":"evil.php"}`,
		map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator quarantine: want 403, got %d", rec.Code)
	}
}

// 隔离的 path 经 SafeJoin 钳制回 scan_dir 内,绝不会动到 scan_dir 外的真实文件
// (如 /etc/passwd)。钳后路径不存在 -> 移动失败 500,但宿主文件安然无恙。
func TestQuarantineCannotEscapeRoot(t *testing.T) {
	_, h, dir, _ := testMod(t, "admin")
	// 在钳制目标位置放一个文件,证明被操作的是 scan_dir 内的钳后路径而非宿主 /etc/passwd。
	writeSample(t, dir, "etc/passwd", "decoy")
	rec := req(t, h, http.MethodPost, "/quarantine", `{"path":"../../etc/passwd"}`,
		map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("clamped quarantine: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var res map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if !strings.HasPrefix(res["orig_path"], dir) {
		t.Errorf("quarantined path must stay within scan_dir, got %q", res["orig_path"])
	}
}

func TestQuarantineAndRestoreFlow(t *testing.T) {
	m, h, dir, _ := testMod(t, "admin")
	seedShell(t, dir, "evil.php")
	orig := filepath.Join(dir, "evil.php")

	// 隔离:文件应从原位移走。
	rec := req(t, h, http.MethodPost, "/quarantine", `{"path":"evil.php"}`,
		map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("quarantine: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	if _, err := os.Lstat(orig); !os.IsNotExist(err) {
		t.Errorf("original file must be moved away after quarantine")
	}
	qs, _ := m.ms.listQuarantine()
	if len(qs) != 1 {
		t.Fatalf("want 1 quarantine record, got %d", len(qs))
	}
	if _, err := os.Stat(qs[0].StoredPath); err != nil {
		t.Errorf("stored file should exist in quarantine dir: %v", err)
	}

	// 还原:文件回到原位。
	rec = req(t, h, http.MethodPost, "/restore", `{"path":"evil.php"}`,
		map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("restore: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	if _, err := os.Stat(orig); err != nil {
		t.Errorf("file must be restored to original path: %v", err)
	}
	qs, _ = m.ms.listQuarantine()
	if len(qs) != 0 {
		t.Errorf("quarantine list should be empty after restore, got %d", len(qs))
	}
}

func TestDeleteRequiresConfirm(t *testing.T) {
	_, h, dir, _ := testMod(t, "admin")
	seedShell(t, dir, "evil.php")
	rec := req(t, h, http.MethodPost, "/delete", `{"path":"evil.php"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("delete w/o confirm: want 428, got %d", rec.Code)
	}
}

func TestDeleteRequiresAdmin(t *testing.T) {
	_, h, dir, _ := testMod(t, "operator")
	seedShell(t, dir, "evil.php")
	rec := req(t, h, http.MethodPost, "/delete", `{"path":"evil.php"}`,
		map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator delete: want 403, got %d", rec.Code)
	}
}

func TestDeleteRemovesHitFile(t *testing.T) {
	_, h, dir, audits := testMod(t, "admin")
	seedShell(t, dir, "evil.php")
	orig := filepath.Join(dir, "evil.php")

	rec := req(t, h, http.MethodPost, "/delete", `{"path":"evil.php"}`,
		map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	if _, err := os.Lstat(orig); !os.IsNotExist(err) {
		t.Errorf("file must be gone after delete")
	}
	var res map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res["deleted"] != orig {
		t.Errorf("want deleted=%q, got %q", orig, res["deleted"])
	}
	var hasDelete bool
	for _, a := range *audits {
		if strings.HasPrefix(a, "malscan.delete:") && strings.HasSuffix(a, orig) {
			hasDelete = true
		}
	}
	if !hasDelete {
		t.Errorf("delete must be audited with abs path: %v", *audits)
	}
}

// 删除的 path 经 SafeJoin 钳制回 scan_dir 内,绝不会动到 scan_dir 外的真实文件。
// 钳后路径落在 scan_dir 内,宿主 /etc/passwd 安然无恙。
func TestDeleteCannotEscapeRoot(t *testing.T) {
	_, h, dir, _ := testMod(t, "admin")
	writeSample(t, dir, "etc/passwd", "decoy")
	clamped := filepath.Join(dir, "etc/passwd")
	rec := req(t, h, http.MethodPost, "/delete", `{"path":"../../etc/passwd"}`,
		map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("clamped delete: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var res map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res["deleted"] != clamped {
		t.Errorf("deleted path must be clamped within scan_dir, got %q", res["deleted"])
	}
}

// 软链逃逸:scan_dir 内软链指向外部文件,SafeJoin 必须拒绝删除,外部文件不受影响。
func TestDeleteRejectsSymlinkEscape(t *testing.T) {
	_, h, dir, _ := testMod(t, "admin")
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("keep me"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	link := filepath.Join(dir, "evil_link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	rec := req(t, h, http.MethodPost, "/delete", `{"path":"evil_link"}`,
		map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("symlink-escape delete: want 400, got %d (%s)", rec.Code, rec.Body)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("outside file must survive rejected delete: %v", err)
	}
}

func TestWhitelistExcludesFromScan(t *testing.T) {
	_, h, dir, _ := testMod(t, "operator")
	seedShell(t, dir, "evil.php")

	// 加白名单。
	rec := req(t, h, http.MethodPost, "/whitelist", `{"path":"evil.php"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("whitelist add: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	// 扫描:白名单文件不应命中。
	rec = req(t, h, http.MethodPost, "/scan", `{}`, nil)
	var task Task
	_ = json.Unmarshal(rec.Body.Bytes(), &task)
	if task.FlaggedCount != 0 {
		t.Errorf("whitelisted file must not be flagged, got %d", task.FlaggedCount)
	}
}

func TestSettingsRequireAdmin(t *testing.T) {
	_, h, _, _ := testMod(t, "operator")
	rec := req(t, h, http.MethodGet, "/settings", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator get settings: want 403, got %d", rec.Code)
	}
	rec = req(t, h, http.MethodPut, "/settings",
		`{"scan_dir":"/tmp/x","quarantine_dir":"/tmp/q","max_file_size":1,"max_files":1,"score_to_flag":1}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator put settings: want 403, got %d", rec.Code)
	}
}

func TestSettingsRejectRelativePaths(t *testing.T) {
	_, h, _, _ := testMod(t, "admin")
	rec := req(t, h, http.MethodPut, "/settings",
		`{"scan_dir":"relative/dir","quarantine_dir":"/tmp/q","max_file_size":1,"max_files":1,"score_to_flag":1}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("relative scan_dir: want 400, got %d", rec.Code)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	_, h, _, _ := testMod(t, "admin")
	body := `{"scan_dir":"/www/site","quarantine_dir":"/www/quar","max_file_size":1024,"max_files":10,"score_to_flag":5}`
	rec := req(t, h, http.MethodPut, "/settings", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put settings: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	rec = req(t, h, http.MethodGet, "/settings", "", nil)
	var s Settings
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	if s.ScanDir != "/www/site" || s.MaxFiles != 10 || s.ScoreToFlag != 5 {
		t.Errorf("settings not persisted: %+v", s)
	}
}

func TestRulesEndpointListsBuiltins(t *testing.T) {
	_, h, _, _ := testMod(t, "viewer")
	rec := req(t, h, http.MethodGet, "/rules", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rules: want 200, got %d", rec.Code)
	}
	var rules []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rules)
	if len(rules) != len(builtinRules) {
		t.Errorf("want %d rules, got %d", len(builtinRules), len(rules))
	}
}

func TestMetaIsSwitchableSecurity(t *testing.T) {
	m, _, _, _ := testMod(t, "admin")
	meta := m.Meta()
	if meta.ID != "malscan" || meta.Category != "安全" || meta.AlwaysOn {
		t.Errorf("unexpected meta: %+v", meta)
	}
}
