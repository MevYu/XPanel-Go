package database

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// mockDumpRestore 记录调用并捕获接收到的设置,用于断言凭证不进 argv、库名校验等。
type mockDumpRestore struct {
	dumpEngine, dumpDB, dumpDest string
	restoreEngine, restoreDB     string
	restoreSrc                   string
	gotSettings                  Settings
	dumpErr, restoreErr          error
	dumpSize                     int64
	content                      string // 写入 destFile 的内容(默认非空,模拟真实转储)
}

func (m *mockDumpRestore) dump(_ context.Context, engine, dbName, destFile string, s Settings) (int64, error) {
	m.dumpEngine, m.dumpDB, m.dumpDest, m.gotSettings = engine, dbName, destFile, s
	if m.dumpErr != nil {
		return 0, m.dumpErr
	}
	c := m.content
	if c == "" {
		c = "dump-bytes"
	}
	if err := os.WriteFile(destFile, []byte(c), 0o600); err != nil {
		return 0, err
	}
	return int64(len(c)), nil
}

func (m *mockDumpRestore) restore(_ context.Context, engine, dbName, srcFile string, s Settings) error {
	m.restoreEngine, m.restoreDB, m.restoreSrc, m.gotSettings = engine, dbName, srcFile, s
	return m.restoreErr
}

// newBackupModule 装配一个用临时 backup_dir + mock dumper 的模块。
func newBackupModule(t *testing.T, role string, audited *int) (*Module, *mockDumpRestore) {
	t.Helper()
	dir := t.TempDir()
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 7, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	}
	m := New("test-secret", newTestStore(t), deps)
	if err := m.ss.save(Settings{BackupDir: dir, MySQLPassword: "p@ss", PGPassword: "pg-secret"}); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	dr := &mockDumpRestore{}
	m.dumper = dr
	return m, dr
}

func TestBackupCreateMySQL(t *testing.T) {
	audited := 0
	m, dr := newBackupModule(t, "admin", &audited)
	rec := do(router(m), "POST", "/mysql/databases/my_app/backup", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("backup = %d, body %s", rec.Code, rec.Body)
	}
	if dr.dumpEngine != "mysql" || dr.dumpDB != "my_app" {
		t.Errorf("dump got engine=%q db=%q", dr.dumpEngine, dr.dumpDB)
	}
	if !strings.HasSuffix(dr.dumpDest, ".sql.gz") {
		t.Errorf("dest should end .sql.gz, got %q", dr.dumpDest)
	}
	if audited != 1 {
		t.Errorf("backup should audit once, got %d", audited)
	}
	// 记录已落库
	rec = do(router(m), "GET", "/backups", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list backups = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "my_app") || !strings.Contains(rec.Body.String(), "mysql") {
		t.Errorf("list body missing record: %s", rec.Body)
	}
}

func TestBackupCreatePassesSettingsNotArgv(t *testing.T) {
	// 凭证只通过 Settings 传入 dumper(由 dumper 用环境变量喂给子进程),不出现在 handler 拼的任何 argv。
	m, dr := newBackupModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/postgres/databases/app/backup", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pg backup = %d body %s", rec.Code, rec.Body)
	}
	if dr.gotSettings.PGPassword != "pg-secret" {
		t.Errorf("dumper should receive decrypted PG password, got %q", dr.gotSettings.PGPassword)
	}
	if dr.dumpEngine != "postgres" {
		t.Errorf("engine = %q", dr.dumpEngine)
	}
}

func TestBackupRejectsBadEngine(t *testing.T) {
	m, _ := newBackupModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/redis/databases/x/backup", "", nil)
	if rec.Code == http.StatusOK {
		t.Errorf("redis engine should not be backup-able, got %d", rec.Code)
	}
}

func TestBackupRejectsInjectionDBName(t *testing.T) {
	m, dr := newBackupModule(t, "admin", new(int))
	// chi 会把含 '/' 的拒成 404;测无斜杠但非法字符
	for _, name := range []string{"bad;name", "a.b", "x-y"} {
		rec := do(router(m), "POST", "/mysql/databases/"+name+"/backup", "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("db %q should be 400, got %d", name, rec.Code)
		}
	}
	if dr.dumpDB != "" {
		t.Errorf("injection must not reach dumper, got %q", dr.dumpDB)
	}
}

func TestBackupNonAdminForbidden(t *testing.T) {
	audited := 0
	m, _ := newBackupModule(t, "operator", &audited)
	r := router(m)
	cases := []struct{ method, path string }{
		{"POST", "/mysql/databases/d/backup"},
		{"GET", "/backups"},
		{"POST", "/backups/1/restore"},
		{"GET", "/backups/1/download"},
		{"DELETE", "/backups/1"},
	}
	for _, c := range cases {
		rec := do(r, c.method, c.path, "", map[string]string{"X-Confirm-Danger": "y"})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", c.method, c.path, rec.Code)
		}
	}
	if audited != 0 {
		t.Errorf("forbidden must not audit, got %d", audited)
	}
}

func TestRestoreRequiresConfirm(t *testing.T) {
	audited := 0
	m, dr := newBackupModule(t, "admin", &audited)
	r := router(m)
	// 先建一条备份
	do(r, "POST", "/mysql/databases/my_app/backup", "", nil)
	audited = 0
	// 无确认头 → 428
	rec := do(r, "POST", "/backups/1/restore", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("restore without confirm = %d, want 428", rec.Code)
	}
	if dr.restoreDB != "" || audited != 0 {
		t.Errorf("unconfirmed restore must not run/audit")
	}
	// 带确认头 → 执行
	rec = do(r, "POST", "/backups/1/restore", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed restore = %d body %s", rec.Code, rec.Body)
	}
	if dr.restoreEngine != "mysql" || dr.restoreDB != "my_app" {
		t.Errorf("restore got engine=%q db=%q", dr.restoreEngine, dr.restoreDB)
	}
	if audited != 1 {
		t.Errorf("restore should audit once, got %d", audited)
	}
}

func TestDeleteRequiresConfirm(t *testing.T) {
	m, _ := newBackupModule(t, "admin", new(int))
	r := router(m)
	do(r, "POST", "/mysql/databases/my_app/backup", "", nil)
	rec := do(r, "DELETE", "/backups/1", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("delete without confirm = %d, want 428", rec.Code)
	}
	rec = do(r, "DELETE", "/backups/1", "", map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed delete = %d", rec.Code)
	}
	// 已删:再查列表应为空
	rec = do(r, "GET", "/backups", "", nil)
	if strings.Contains(rec.Body.String(), "my_app") {
		t.Errorf("record should be deleted: %s", rec.Body)
	}
}

func TestDeleteRemovesFile(t *testing.T) {
	m, dr := newBackupModule(t, "admin", new(int))
	r := router(m)
	do(r, "POST", "/mysql/databases/my_app/backup", "", nil)
	if _, err := os.Stat(dr.dumpDest); err != nil {
		t.Fatalf("backup file should exist: %v", err)
	}
	do(r, "DELETE", "/backups/1", "", map[string]string{"X-Confirm-Danger": "1"})
	if _, err := os.Stat(dr.dumpDest); !os.IsNotExist(err) {
		t.Errorf("backup file should be removed, stat err = %v", err)
	}
}

func TestDownloadServesFile(t *testing.T) {
	m, _ := newBackupModule(t, "admin", new(int))
	r := router(m)
	do(r, "POST", "/mysql/databases/my_app/backup", "", nil)
	rec := do(r, "GET", "/backups/1/download", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("download = %d", rec.Code)
	}
	if rec.Body.String() != "dump-bytes" {
		t.Errorf("download body = %q", rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, ".sql.gz") {
		t.Errorf("missing/empty Content-Disposition: %q", cd)
	}
}

func TestRestoreRejectsPathTraversal(t *testing.T) {
	// 直接构造一条 filename 含穿越的记录,确认 restore/download/delete 拒绝越出 backup_dir。
	dir := t.TempDir()
	audited := 0
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 1, "admin" },
		Audit:     func(*int64, string, string, string) { audited++ },
	}
	m := New("s", newTestStore(t), deps)
	if err := m.ss.save(Settings{BackupDir: dir}); err != nil {
		t.Fatal(err)
	}
	dr := &mockDumpRestore{}
	m.dumper = dr
	// 写一个 backup_dir 外的目标文件,filename 用穿越指向它
	outside := filepath.Join(filepath.Dir(dir), "secret.sql.gz")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := m.bs.insert("mysql", "db", "../"+filepath.Base(outside), 1)
	if err != nil {
		t.Fatal(err)
	}
	r := router(m)
	ids := strconv.FormatInt(id, 10)
	rec := do(r, "POST", "/backups/"+ids+"/restore", "", map[string]string{"X-Confirm-Danger": "y"})
	if rec.Code == http.StatusNoContent {
		t.Errorf("traversal restore should be rejected, got %d", rec.Code)
	}
	if dr.restoreDB != "" {
		t.Errorf("traversal must not reach restorer")
	}
	rec = do(r, "GET", "/backups/"+ids+"/download", "", nil)
	if rec.Code == http.StatusOK {
		t.Errorf("traversal download should be rejected, got %d", rec.Code)
	}
}

func TestBackupRecordCRUDStore(t *testing.T) {
	st := newTestStore(t)
	cryp, _ := newCryptor("s")
	ss, _ := newSettingsStore(st, cryp)
	bs, err := newBackupStore(st)
	if err != nil {
		t.Fatal(err)
	}
	_ = ss
	id, err := bs.insert("mysql", "app", "app-20260101.sql.gz", 123)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := bs.list()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].DBName != "app" || recs[0].Size != 123 || recs[0].Engine != "mysql" {
		t.Errorf("list = %+v", recs)
	}
	got, err := bs.get(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Filename != "app-20260101.sql.gz" || got.CreatedAt == "" {
		t.Errorf("get = %+v", got)
	}
	if err := bs.delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.get(id); err == nil {
		t.Errorf("get after delete should error")
	}
}
