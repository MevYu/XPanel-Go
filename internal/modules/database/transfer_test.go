package database

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockDump 记录导出/导入调用并按需注入内容/错误。
type mockDump struct {
	exportDB   string
	importDB   string
	exportBody string // export 时写入 w 的内容
	importGot  string // import 时从 r 读到的内容
	importErr  error
}

func (m *mockDump) export(_ context.Context, _ dialect, db string, _ Settings, w io.Writer) error {
	m.exportDB = db
	_, err := io.WriteString(w, m.exportBody)
	return err
}

func (m *mockDump) importSQL(_ context.Context, _ dialect, db string, _ Settings, r io.Reader) error {
	m.importDB = db
	b, _ := io.ReadAll(r)
	m.importGot = string(b)
	return m.importErr
}

func withMockDump(m *Module) *mockDump {
	md := &mockDump{exportBody: "-- dump\nCREATE TABLE t(id INT);\n"}
	m.dumpRun = md
	return md
}

func TestExportRequiresAdmin(t *testing.T) {
	m, _, _ := newTestModule(t, "operator", new(int))
	withMockDump(m)
	rec := do(router(m), "GET", "/mysql/export?database=app", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin export = %d, want 403", rec.Code)
	}
}

func TestExportRejectsBadDBName(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	md := withMockDump(m)
	rec := do(router(m), "GET", "/mysql/export?database=a;DROP", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad db export = %d, want 400", rec.Code)
	}
	if md.exportDB != "" {
		t.Errorf("rejected export must not reach runner, got %q", md.exportDB)
	}
}

func TestExportPlainAndAudit(t *testing.T) {
	audited := 0
	m, _, _ := newTestModule(t, "admin", &audited)
	md := withMockDump(m)
	rec := do(router(m), "GET", "/mysql/export?database=app", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	if md.exportDB != "app" {
		t.Errorf("runner got db %q, want app", md.exportDB)
	}
	if !strings.Contains(rec.Body.String(), "CREATE TABLE t") {
		t.Errorf("export body = %q", rec.Body.String())
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, `filename="app.sql"`) {
		t.Errorf("content-disposition = %q", cd)
	}
	if audited != 1 {
		t.Errorf("export should audit once, got %d", audited)
	}
}

func TestExportGzip(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	withMockDump(m)
	rec := do(router(m), "GET", "/mysql/export?database=app&gzip=1", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("gzip export = %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="app.sql.gz"`) {
		t.Errorf("gzip filename = %q", cd)
	}
	gzr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("body not gzip: %v", err)
	}
	out, _ := io.ReadAll(gzr)
	if !strings.Contains(string(out), "CREATE TABLE t") {
		t.Errorf("decompressed = %q", out)
	}
}

func TestImportRequiresConfirm(t *testing.T) {
	audited := 0
	m, _, _ := newTestModule(t, "admin", &audited)
	md := withMockDump(m)
	// 无确认头 → 428
	rec := do(router(m), "POST", "/mysql/import?database=app", "SELECT 1;", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("import without confirm = %d, want 428", rec.Code)
	}
	if md.importDB != "" || audited != 0 {
		t.Errorf("unconfirmed import must not run/audit")
	}
	// 带确认头 → 执行
	rec = do(router(m), "POST", "/mysql/import?database=app", "SELECT 1;",
		map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed import = %d", rec.Code)
	}
	if md.importDB != "app" || md.importGot != "SELECT 1;" {
		t.Errorf("import runner db=%q got=%q", md.importDB, md.importGot)
	}
	if audited != 1 {
		t.Errorf("import should audit once, got %d", audited)
	}
}

func TestImportRejectsBadDBName(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	md := withMockDump(m)
	rec := do(router(m), "POST", "/mysql/import?database=a%20b", "x",
		map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad db import = %d, want 400", rec.Code)
	}
	if md.importDB != "" {
		t.Error("rejected import must not reach runner")
	}
}

func TestRedisConfig(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "GET", "/redis/config", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("redis config = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "maxmemory") {
		t.Errorf("config body = %s", rec.Body)
	}
}

func TestRedisDetails(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "GET", "/redis/details", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("redis details = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "connected_clients") || !strings.Contains(body, "used_memory") {
		t.Errorf("details body = %s", body)
	}
}

func TestRedisDetailsRequiresAdmin(t *testing.T) {
	m, _, _ := newTestModule(t, "readonly", new(int))
	for _, p := range []string{"/redis/config", "/redis/details"} {
		rec := do(router(m), "GET", p, "", nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("non-admin %s = %d, want 403", p, rec.Code)
		}
	}
}
