package cron

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// fakeCrontab 把一个假的 crontab 脚本放到 PATH 最前,使写路径既可控又不动宿主真实 crontab。
// 脚本把内容存进 tmp 文件: crontab -l 回读,crontab - 从 stdin 覆写。
func fakeCrontab(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	script := "#!/bin/sh\n" +
		"SPOOL=\"" + spool + "\"\n" +
		"if [ \"$1\" = \"-l\" ]; then\n" +
		"  if [ -f \"$SPOOL\" ]; then cat \"$SPOOL\"; else echo \"no crontab for test\" >&2; exit 1; fi\n" +
		"elif [ \"$1\" = \"-\" ]; then\n" +
		"  cat > \"$SPOOL\"\n" +
		"fi\n"
	if err := os.WriteFile(filepath.Join(dir, "crontab"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake crontab: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// newTestModule 建一个挂好路由的模块,principal 返回给定角色。
func newTestModule(t *testing.T, role string) (*Module, http.Handler, *[]string) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	var audits []string
	m := New(st, Deps{
		Principal: func(*http.Request) (int64, string) { return 42, role },
		Audit: func(_ *int64, action, detail, _ string) {
			audits = append(audits, action+":"+detail)
		},
	})
	r := chi.NewRouter()
	m.Routes(r)
	return m, r, &audits
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCreateRequiresOperator(t *testing.T) {
	fakeCrontab(t)
	_, h, _ := newTestModule(t, "viewer")
	rec := do(t, h, http.MethodPost, "/jobs", `{"expr":"0 3 * * *","command":"/bin/x.sh"}`)
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer create: want 403, got %d", rec.Code)
	}
}

func TestCreateValidatesExpr(t *testing.T) {
	fakeCrontab(t)
	_, h, _ := newTestModule(t, "operator")
	rec := do(t, h, http.MethodPost, "/jobs", `{"expr":"bad","command":"/bin/x.sh"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad expr: want 400, got %d", rec.Code)
	}
}

func TestCreateRejectsCommandInjection(t *testing.T) {
	fakeCrontab(t)
	_, h, _ := newTestModule(t, "operator")
	rec := do(t, h, http.MethodPost, "/jobs", `{"expr":"0 3 * * *","command":"echo a\nrm -rf /"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("newline in command: want 400, got %d", rec.Code)
	}
}

func TestCreateListWritesCrontab(t *testing.T) {
	fakeCrontab(t)
	m, h, audits := newTestModule(t, "operator")

	rec := do(t, h, http.MethodPost, "/jobs",
		`{"expr":"0 3 * * *","command":"/bin/backup.sh","comment":"nightly"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d (%s)", rec.Code, rec.Body)
	}
	var created Job
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.ID == 0 || !created.Enabled || created.CreatedBy == nil || *created.CreatedBy != 42 {
		t.Errorf("unexpected created job: %+v", created)
	}

	// crontab 真被写入,且含我们的任务行。
	ct, err := readSpool(m)
	if err != nil {
		t.Fatalf("read crontab: %v", err)
	}
	if !strings.Contains(ct, "0 3 * * * /bin/backup.sh") {
		t.Errorf("crontab missing job line:\n%s", ct)
	}

	// list 能读到。
	rec = do(t, h, http.MethodGet, "/jobs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rec.Code)
	}
	var jobs []Job
	_ = json.Unmarshal(rec.Body.Bytes(), &jobs)
	if len(jobs) != 1 {
		t.Errorf("want 1 job, got %d", len(jobs))
	}
	if len(*audits) == 0 || !strings.HasPrefix((*audits)[0], "cron.create:") {
		t.Errorf("create audit not written: %v", *audits)
	}
}

func TestDisableRemovesFromCrontab(t *testing.T) {
	fakeCrontab(t)
	m, h, _ := newTestModule(t, "operator")
	rec := do(t, h, http.MethodPost, "/jobs", `{"expr":"0 3 * * *","command":"/bin/backup.sh"}`)
	var j Job
	_ = json.Unmarshal(rec.Body.Bytes(), &j)
	idStr := itoa(j.ID)

	rec = do(t, h, http.MethodPost, "/jobs/"+idStr+"/disable", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: want 200, got %d", rec.Code)
	}
	ct, _ := readSpool(m)
	if strings.Contains(ct, "/bin/backup.sh") {
		t.Errorf("disabled job must not appear in crontab:\n%s", ct)
	}

	// 重新启用又出现。
	rec = do(t, h, http.MethodPost, "/jobs/"+idStr+"/enable", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("enable: want 200, got %d", rec.Code)
	}
	ct, _ = readSpool(m)
	if !strings.Contains(ct, "/bin/backup.sh") {
		t.Errorf("re-enabled job must reappear in crontab:\n%s", ct)
	}
}

func TestDeleteRemovesJob(t *testing.T) {
	fakeCrontab(t)
	_, h, _ := newTestModule(t, "admin")
	rec := do(t, h, http.MethodPost, "/jobs", `{"expr":"* * * * *","command":"true"}`)
	var j Job
	_ = json.Unmarshal(rec.Body.Bytes(), &j)

	rec = do(t, h, http.MethodDelete, "/jobs/"+itoa(j.ID), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/jobs", "")
	var jobs []Job
	_ = json.Unmarshal(rec.Body.Bytes(), &jobs)
	if len(jobs) != 0 {
		t.Errorf("want 0 jobs after delete, got %d", len(jobs))
	}
}

func TestUpdateNotFound(t *testing.T) {
	fakeCrontab(t)
	_, h, _ := newTestModule(t, "operator")
	rec := do(t, h, http.MethodPut, "/jobs/999", `{"expr":"* * * * *","command":"true"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("update missing: want 404, got %d", rec.Code)
	}
}

func TestSyncPreservesUserLines(t *testing.T) {
	fakeCrontab(t)
	m, h, _ := newTestModule(t, "operator")
	// 预置一条用户手写任务到 spool。
	if err := os.WriteFile(spoolPath(m), []byte("MAILTO=root\n5 5 * * * /user/own.sh\n"), 0o644); err != nil {
		// spool 还不存在时(首次), 直接写也行
		t.Fatalf("seed spool: %v", err)
	}
	do(t, h, http.MethodPost, "/jobs", `{"expr":"0 3 * * *","command":"/bin/managed.sh"}`)
	ct, _ := readSpool(m)
	if !strings.Contains(ct, "/user/own.sh") {
		t.Errorf("user line lost after managed write:\n%s", ct)
	}
	if !strings.Contains(ct, "/bin/managed.sh") {
		t.Errorf("managed line missing:\n%s", ct)
	}
}

// --- helpers ---

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// spoolPath / readSpool 通过 PATH 里那份 fake crontab 用的 spool 文件回读。
// 我们没有直接句柄,因此从 PATH 上的脚本里解析出 SPOOL 路径。
func spoolPath(_ *Module) string {
	dir := strings.SplitN(os.Getenv("PATH"), string(os.PathListSeparator), 2)[0]
	return filepath.Join(dir, "spool")
}

func readSpool(m *Module) (string, error) {
	b, err := os.ReadFile(spoolPath(m))
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(b), err
}
