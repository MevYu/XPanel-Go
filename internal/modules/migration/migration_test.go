package migration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func itoa(id int64) string { return strconv.FormatInt(id, 10) }

func openIfExists(path string) (*os.File, error) { return os.Open(path) }

func testModule(t *testing.T, role string, audited *int) *Module {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(_ *int64, _, _, _ string) { *audited++ },
	})
}

func router(m *Module) chi.Router {
	r := chi.NewRouter()
	m.Routes(r)
	return r
}

// --- mocks ---

type mockPacker struct {
	packed     bool
	unpacked   bool
	manifest   Meta
	manifErr   error
	hasDB      bool
	packSize   int64
	lastSiteDe string
}

func (p *mockPacker) pack(siteRoot, dbDump string, meta Meta, destFile string) (int64, error) {
	p.packed = true
	return p.packSize, nil
}
func (p *mockPacker) readManifest(string) (Meta, error) { return p.manifest, p.manifErr }
func (p *mockPacker) unpack(_, siteDest, _ string) (bool, error) {
	p.unpacked = true
	p.lastSiteDe = siteDest
	return p.hasDB, nil
}

type mockDumper struct {
	called  bool
	err     error         // 非空则 dump 返回该错误(注入导出失败)
	started chan struct{} // 非空时:dump 启动后关闭,供测试感知任务已在跑
	release chan struct{} // 非空时:dump 阻塞直到该通道关闭/有信号
}

func (d *mockDumper) dump(_, _, dest string, _ Settings) (int64, error) {
	d.called = true
	if d.started != nil {
		close(d.started)
	}
	if d.release != nil {
		<-d.release
	}
	if d.err != nil {
		return 0, d.err
	}
	return 0, nil
}

type mockRestorer struct{ called bool }

func (r *mockRestorer) restore(_, _, _ string, _ Settings) error {
	r.called = true
	return nil
}

// --- meta / nav ---

func TestMetaSwitchable(t *testing.T) {
	m := testModule(t, "admin", new(int))
	meta := m.Meta()
	if meta.ID != "migration" || meta.AlwaysOn {
		t.Errorf("must be id=migration, not AlwaysOn, got %+v", meta)
	}
	if meta.Category != "系统" {
		t.Errorf("category = %q", meta.Category)
	}
	if nav := m.Nav(); len(nav) != 1 || nav[0].Path != "/migration" {
		t.Errorf("nav = %+v", nav)
	}
}

func TestHealthCheckOK(t *testing.T) {
	if err := (&Module{}).HealthCheck(); err != nil {
		t.Errorf("HealthCheck should pass (stdlib packing): %v", err)
	}
}

// --- settings ---

func TestSettingsRoundTripDefaults(t *testing.T) {
	audited := 0
	m := testModule(t, "admin", &audited)
	r := router(m)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/settings", nil))
	if rec.Code != 200 {
		t.Fatalf("get settings %d", rec.Code)
	}
	var s Settings
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	if s.MigrationDir != defaultMigrationDir || s.MysqlDump != "mysqldump" || s.MysqlCLI != "mysql" {
		t.Errorf("defaults wrong: %+v", s)
	}

	body, _ := json.Marshal(Settings{MigrationDir: "/srv/mig"})
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("PUT", "/settings", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("put settings %d", rec.Code)
	}
	got, _ := m.ms.settings()
	if got.MigrationDir != "/srv/mig" {
		t.Errorf("migration_dir = %q", got.MigrationDir)
	}
	// 空字段回落默认
	if got.MysqlDump != "mysqldump" {
		t.Errorf("empty mysqldump should fall back, got %q", got.MysqlDump)
	}
}

func TestSettingsRequiresAdmin(t *testing.T) {
	m := testModule(t, "operator", new(int))
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("GET", "/settings", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin settings should 403, got %d", rec.Code)
	}
}

// --- export ---

func TestExportRequiresAdmin(t *testing.T) {
	audited := 0
	m := testModule(t, "operator", &audited)
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("POST", "/export", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin export should 403, got %d", rec.Code)
	}
	if audited != 0 {
		t.Fatalf("forbidden must not audit, got %d", audited)
	}
}

func TestExportRejectsRelativeSitePath(t *testing.T) {
	m := testModule(t, "admin", new(int))
	body, _ := json.Marshal(exportRequest{SitePath: "relative/path"})
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("POST", "/export", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("relative site_path should 400, got %d", rec.Code)
	}
}

func TestExportRejectsBadDBKind(t *testing.T) {
	m := testModule(t, "admin", new(int))
	body, _ := json.Marshal(exportRequest{SitePath: "/tmp/x", DBKind: "mongo"})
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("POST", "/export", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad db_kind should 400, got %d", rec.Code)
	}
}

func TestExportRejectsBadDBName(t *testing.T) {
	m := testModule(t, "admin", new(int))
	site := t.TempDir()
	body, _ := json.Marshal(exportRequest{SitePath: site, DBKind: "mysql", DBName: "bad;name"})
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("POST", "/export", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad db_name should 400, got %d", rec.Code)
	}
}

func TestExportSucceedsAndAudits(t *testing.T) {
	audited := 0
	m := testModule(t, "admin", &audited)
	mp := &mockPacker{packSize: 123}
	md := &mockDumper{}
	m.pk, m.dmp = mp, md

	site := t.TempDir()
	_ = m.ms.saveSettings(Settings{MigrationDir: t.TempDir()})
	body, _ := json.Marshal(exportRequest{SitePath: site, Domain: "ex.com", DBKind: "mysql", DBName: "shop"})
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("POST", "/export", bytes.NewReader(body)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("export should 202, got %d (%s)", rec.Code, rec.Body.String())
	}
	id := taskIDFromBody(t, rec.Body.Bytes())
	task := waitTask(t, m, id)
	if task.Status != "success" {
		t.Fatalf("export task should succeed, got %+v", task)
	}
	if !mp.packed || !md.called {
		t.Errorf("expected pack+dump called: pack=%v dump=%v", mp.packed, md.called)
	}
	if audited != 1 {
		t.Errorf("export should audit once, got %d", audited)
	}
	// 落库可查
	list, _ := m.ms.listPackages()
	if len(list) != 1 {
		t.Errorf("expected 1 package recorded, got %d", len(list))
	}
	if list[0].Size != 123 || list[0].DBName != "shop" {
		t.Errorf("package record wrong: %+v", list[0])
	}
}

// --- import (danger) ---

func TestImportRequiresAdmin(t *testing.T) {
	m := testModule(t, "operator", new(int))
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("POST", "/import", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin import should 403, got %d", rec.Code)
	}
}

func TestImportRequiresConfirmHeader(t *testing.T) {
	m := testModule(t, "admin", new(int))
	body, _ := json.Marshal(importRequest{PackageID: 1, SiteDest: "/tmp/dest"})
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("POST", "/import", bytes.NewReader(body)))
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("import without confirm should 428, got %d", rec.Code)
	}
}

func TestImportRejectsRelativeDest(t *testing.T) {
	m := testModule(t, "admin", new(int))
	body, _ := json.Marshal(importRequest{PackageID: 1, SiteDest: "rel/dest"})
	req := httptest.NewRequest("POST", "/import", bytes.NewReader(body))
	req.Header.Set("X-Confirm-Danger", "yes")
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("relative site_dest should 400, got %d", rec.Code)
	}
}

func TestImportUnknownPackage(t *testing.T) {
	m := testModule(t, "admin", new(int))
	body, _ := json.Marshal(importRequest{PackageID: 999, SiteDest: "/tmp/dest"})
	req := httptest.NewRequest("POST", "/import", bytes.NewReader(body))
	req.Header.Set("X-Confirm-Danger", "yes")
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown package should 400, got %d", rec.Code)
	}
}

func TestImportRestoresSiteAndDBAndAudits(t *testing.T) {
	audited := 0
	m := testModule(t, "admin", &audited)
	mp := &mockPacker{manifest: Meta{DBKind: "mysql", DBName: "shop"}, hasDB: true}
	mr := &mockRestorer{}
	m.pk, m.rst = mp, mr
	_ = m.ms.saveSettings(Settings{MigrationDir: t.TempDir()})

	pkg, _ := m.ms.addPackage(Package{Name: "n", Filename: "p.tar.gz", DBKind: "mysql", DBName: "shop"})
	dest := t.TempDir()
	body, _ := json.Marshal(importRequest{PackageID: pkg.ID, SiteDest: dest, ImportDB: true})
	req := httptest.NewRequest("POST", "/import", bytes.NewReader(body))
	req.Header.Set("X-Confirm-Danger", "yes")
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("import should 202, got %d (%s)", rec.Code, rec.Body.String())
	}
	task := waitTask(t, m, taskIDFromBody(t, rec.Body.Bytes()))
	if task.Status != "success" {
		t.Fatalf("import task should succeed, got %+v", task)
	}
	if !mp.unpacked || !mr.called {
		t.Errorf("expected unpack+restore: unpack=%v restore=%v", mp.unpacked, mr.called)
	}
	if mp.lastSiteDe != dest {
		t.Errorf("unpack site dest = %q want %q", mp.lastSiteDe, dest)
	}
	if audited != 1 {
		t.Errorf("import should audit once, got %d", audited)
	}
}

func TestImportSiteOnlySkipsRestore(t *testing.T) {
	m := testModule(t, "admin", new(int))
	mp := &mockPacker{manifest: Meta{DBKind: "mysql", DBName: "shop"}, hasDB: true}
	mr := &mockRestorer{}
	m.pk, m.rst = mp, mr
	_ = m.ms.saveSettings(Settings{MigrationDir: t.TempDir()})

	pkg, _ := m.ms.addPackage(Package{Name: "n", Filename: "p.tar.gz"})
	body, _ := json.Marshal(importRequest{PackageID: pkg.ID, SiteDest: t.TempDir(), ImportDB: false})
	req := httptest.NewRequest("POST", "/import", bytes.NewReader(body))
	req.Header.Set("X-Confirm-Danger", "yes")
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("import should 202, got %d", rec.Code)
	}
	task := waitTask(t, m, taskIDFromBody(t, rec.Body.Bytes()))
	if task.Status != "success" {
		t.Fatalf("import task should succeed, got %+v", task)
	}
	if mr.called {
		t.Error("restore must not run when import_db=false")
	}
}

// --- packages list / delete / download ---

func TestDeletePackageRequiresAdmin(t *testing.T) {
	m := testModule(t, "operator", new(int))
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("DELETE", "/packages/1", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin delete should 403, got %d", rec.Code)
	}
}

func TestDeletePackageRemovesFileAndRecord(t *testing.T) {
	audited := 0
	m := testModule(t, "admin", &audited)
	dir := t.TempDir()
	_ = m.ms.saveSettings(Settings{MigrationDir: dir})
	pkgFile := filepath.Join(dir, "p.tar.gz")
	mustWrite(t, pkgFile, "data")
	pkg, _ := m.ms.addPackage(Package{Name: "n", Filename: "p.tar.gz"})

	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("DELETE", "/packages/"+itoa(pkg.ID), nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete should 204, got %d", rec.Code)
	}
	if _, err := openIfExists(pkgFile); err == nil {
		t.Error("package file should be removed")
	}
	list, _ := m.ms.listPackages()
	if len(list) != 0 {
		t.Errorf("record should be deleted, got %d", len(list))
	}
}

func TestDownloadStreamsPackage(t *testing.T) {
	audited := 0
	m := testModule(t, "admin", &audited)
	dir := t.TempDir()
	_ = m.ms.saveSettings(Settings{MigrationDir: dir})
	mustWrite(t, filepath.Join(dir, "p.tar.gz"), "PKGBYTES")
	pkg, _ := m.ms.addPackage(Package{Name: "n", Filename: "p.tar.gz"})

	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("GET", "/packages/"+itoa(pkg.ID)+"/download", nil))
	if rec.Code != 200 {
		t.Fatalf("download should 200, got %d", rec.Code)
	}
	if rec.Body.String() != "PKGBYTES" {
		t.Errorf("body = %q", rec.Body.String())
	}
	if audited != 1 {
		t.Errorf("download should audit once, got %d", audited)
	}
}

func TestManifestPreview(t *testing.T) {
	m := testModule(t, "admin", new(int))
	mp := &mockPacker{manifest: Meta{Domain: "ex.com", PHPVersion: "8.1"}}
	m.pk = mp
	pkg, _ := m.ms.addPackage(Package{Name: "n", Filename: "p.tar.gz"})

	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("GET", "/packages/"+itoa(pkg.ID)+"/manifest", nil))
	if rec.Code != 200 {
		t.Fatalf("manifest should 200, got %d", rec.Code)
	}
	var got Meta
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Domain != "ex.com" || got.PHPVersion != "8.1" {
		t.Errorf("manifest = %+v", got)
	}
}
