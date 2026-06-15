package backup

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

// --- mocks ---

type mockArchiver struct {
	archived  []string // 记录被打包的 dest
	extracted []string // 记录被解包的 dest root
	failArc   bool
}

func (a *mockArchiver) archive(srcRoot, rel, destFile string) (int64, error) {
	if a.failArc {
		return 0, errUnsafeEntry
	}
	a.archived = append(a.archived, destFile)
	_ = os.WriteFile(destFile, []byte("ARCHIVE"), 0o644)
	return int64(len("ARCHIVE")), nil
}

func (a *mockArchiver) extract(srcFile, destRoot string) error {
	a.extracted = append(a.extracted, destRoot)
	return nil
}

type mockDumper struct{ dumped []string }

func (d *mockDumper) dump(kind, dbName, destFile string, s Settings) (int64, error) {
	d.dumped = append(d.dumped, dbName)
	_ = os.WriteFile(destFile, []byte("SQL"), 0o644)
	return 3, nil
}

type mockRclone struct {
	uploaded    []string
	downloaded  []string
	listResult  []string
	configCalls []string
}

func (r *mockRclone) available() error { return nil }
func (r *mockRclone) configCreate(rm Remote) error {
	r.configCalls = append(r.configCalls, rm.Name)
	return nil
}
func (r *mockRclone) configDelete(name string) error { return nil }
func (r *mockRclone) upload(localFile string, rm Remote) error {
	r.uploaded = append(r.uploaded, localFile)
	return nil
}
func (r *mockRclone) list(rm Remote) ([]string, error) { return r.listResult, nil }
func (r *mockRclone) download(name, localFile string, rm Remote) error {
	r.downloaded = append(r.downloaded, name)
	_ = os.WriteFile(localFile, []byte("FETCHED"), 0o644)
	return nil
}

// --- harness ---

type harness struct {
	m       *Module
	arc     *mockArchiver
	dmp     *mockDumper
	rc      *mockRclone
	auditN  int
	backupD string
}

func newHarness(t *testing.T, role string) *harness {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	h := &harness{
		arc:     &mockArchiver{},
		dmp:     &mockDumper{},
		rc:      &mockRclone{},
		backupD: t.TempDir(),
	}
	m := New("secret", st, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { h.auditN++ },
	})
	m.arc, m.dmp, m.rc = h.arc, h.dmp, h.rc
	h.m = m
	// 配置本地备份目录到临时目录
	if err := m.bs.saveSettings(Settings{BackupDir: h.backupD}); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) router() chi.Router {
	r := chi.NewRouter()
	h.m.Routes(r)
	return r
}

func do(t *testing.T, r chi.Router, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// --- tests ---

func TestNonAdminForbidden(t *testing.T) {
	h := newHarness(t, "operator")
	r := h.router()
	cases := []struct{ method, path, body string }{
		{"GET", "/settings", ""},
		{"PUT", "/settings", "{}"},
		{"GET", "/remotes", ""},
		{"POST", "/remotes", `{"name":"s3","type":"s3"}`},
		{"GET", "/jobs", ""},
		{"POST", "/run", `{"target_kind":"path","target":"/tmp/x"}`},
		{"GET", "/records", ""},
	}
	for _, c := range cases {
		rec := do(t, r, c.method, c.path, c.body, nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as operator = %d, want 403", c.method, c.path, rec.Code)
		}
	}
}

func TestSettingsAdminRoundTrip(t *testing.T) {
	h := newHarness(t, "admin")
	r := h.router()
	rec := do(t, r, "PUT", "/settings", `{"backup_dir":"/data/bk","mysqldump":"/usr/bin/mysqldump"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put settings = %d", rec.Code)
	}
	rec = do(t, r, "GET", "/settings", "", nil)
	var s Settings
	json.Unmarshal(rec.Body.Bytes(), &s)
	if s.BackupDir != "/data/bk" || s.MysqlDump != "/usr/bin/mysqldump" {
		t.Errorf("settings not persisted: %+v", s)
	}
}

func TestRemoteAddNeverLeaksSecret(t *testing.T) {
	h := newHarness(t, "admin")
	r := h.router()
	rec := do(t, r, "POST", "/remotes", `{"name":"s3","type":"s3","bucket":"b","access_key":"AK","secret":"SUPERSECRET"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add remote = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "SUPERSECRET") {
		t.Error("add remote response leaks secret")
	}
	if len(h.rc.configCalls) != 1 {
		t.Errorf("rclone config not created: %v", h.rc.configCalls)
	}
	// list 也不泄露
	rec = do(t, r, "GET", "/remotes", "", nil)
	if strings.Contains(rec.Body.String(), "SUPERSECRET") {
		t.Error("list remotes leaks secret")
	}
}

func TestRemoteInvalidName(t *testing.T) {
	h := newHarness(t, "admin")
	rec := do(t, h.router(), "POST", "/remotes", `{"name":"bad name!","type":"s3"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid remote name = %d, want 400", rec.Code)
	}
}

func TestRunPathBackupAndRecord(t *testing.T) {
	h := newHarness(t, "admin")
	r := h.router()
	rec := do(t, r, "POST", "/run", `{"target_kind":"path","target":"/www/site"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("run = %d body=%s", rec.Code, rec.Body.String())
	}
	if len(h.arc.archived) != 1 {
		t.Errorf("archive not called: %v", h.arc.archived)
	}
	var got Record
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Location != "local" || got.Size == 0 || got.Filename == "" {
		t.Errorf("bad record: %+v", got)
	}
	// 记录已落库
	recs, _ := h.m.bs.listRecords(nil)
	if len(recs) != 1 {
		t.Errorf("record count = %d", len(recs))
	}
}

func TestRunDBBackupUsesDumper(t *testing.T) {
	h := newHarness(t, "admin")
	rec := do(t, h.router(), "POST", "/run", `{"target_kind":"mysql","target":"appdb"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("run db = %d body=%s", rec.Code, rec.Body.String())
	}
	if len(h.dmp.dumped) != 1 || h.dmp.dumped[0] != "appdb" {
		t.Errorf("dumper not used: %v", h.dmp.dumped)
	}
}

func TestRunWithRemoteUploads(t *testing.T) {
	h := newHarness(t, "admin")
	r := h.router()
	// 建远端
	rrec := do(t, r, "POST", "/remotes", `{"name":"s3","type":"s3","bucket":"b","secret":"x"}`, nil)
	var rem Remote
	json.Unmarshal(rrec.Body.Bytes(), &rem)
	body := `{"target_kind":"path","target":"/www/site","remote_id":` + itoa(rem.ID) + `}`
	rec := do(t, r, "POST", "/run", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("run remote = %d body=%s", rec.Code, rec.Body.String())
	}
	if len(h.rc.uploaded) != 1 {
		t.Errorf("upload not called: %v", h.rc.uploaded)
	}
	var got Record
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Location != "remote" || got.RemoteID == nil {
		t.Errorf("remote record wrong: %+v", got)
	}
}

func TestRestoreRequiresConfirm(t *testing.T) {
	h := newHarness(t, "admin")
	r := h.router()
	// 先 run 一个 path 备份产生记录
	do(t, r, "POST", "/run", `{"target_kind":"path","target":"/www/site"}`, nil)
	recs, _ := h.m.bs.listRecords(nil)
	id := itoa(recs[0].ID)

	// 无 confirm → 428
	rec := do(t, r, "POST", "/records/"+id+"/restore", `{"dest":"/tmp/restore"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("restore without confirm = %d, want 428", rec.Code)
	}
	// 带 confirm → 204,extract 被调用
	rec = do(t, r, "POST", "/records/"+id+"/restore", `{"dest":"/tmp/restore"}`, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("restore = %d body=%s", rec.Code, rec.Body.String())
	}
	if len(h.arc.extracted) != 1 || h.arc.extracted[0] != "/tmp/restore" {
		t.Errorf("extract not called with dest: %v", h.arc.extracted)
	}
}

func TestRestoreNonAdminForbidden(t *testing.T) {
	h := newHarness(t, "operator")
	rec := do(t, h.router(), "POST", "/records/1/restore", `{"dest":"/x"}`, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator restore = %d, want 403", rec.Code)
	}
}

func TestDeleteRecordRequiresConfirmAndRemovesFile(t *testing.T) {
	h := newHarness(t, "admin")
	r := h.router()
	do(t, r, "POST", "/run", `{"target_kind":"path","target":"/www/site"}`, nil)
	recs, _ := h.m.bs.listRecords(nil)
	rec0 := recs[0]
	id := itoa(rec0.ID)
	// 文件存在
	if _, err := os.Stat(filepath.Join(h.backupD, rec0.Filename)); err != nil {
		t.Fatalf("backup file missing: %v", err)
	}
	// 无 confirm
	rec := do(t, r, "DELETE", "/records/"+id, "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("delete without confirm = %d", rec.Code)
	}
	// 带 confirm
	rec = do(t, r, "DELETE", "/records/"+id, "", map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(h.backupD, rec0.Filename)); !os.IsNotExist(err) {
		t.Error("backup file not removed on delete")
	}
}

func TestPruneRetention(t *testing.T) {
	h := newHarness(t, "admin")
	r := h.router()
	// 建 job keep=2
	jrec := do(t, r, "POST", "/jobs", `{"name":"nightly","target_kind":"path","target":"/www/site","keep":2}`, nil)
	var job Job
	json.Unmarshal(jrec.Body.Bytes(), &job)
	jid := itoa(job.ID)
	// run 4 次绑定该 job
	for i := 0; i < 4; i++ {
		do(t, r, "POST", "/run", `{"job_id":`+jid+`}`, nil)
	}
	recsBefore, _ := h.m.bs.listRecords(&job.ID)
	if len(recsBefore) != 4 {
		t.Fatalf("expected 4 records, got %d", len(recsBefore))
	}
	// prune
	rec := do(t, r, "POST", "/jobs/"+jid+"/prune", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("prune = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]int
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["removed"] != 2 {
		t.Errorf("removed = %d, want 2", resp["removed"])
	}
	recsAfter, _ := h.m.bs.listRecords(&job.ID)
	if len(recsAfter) != 2 {
		t.Errorf("after prune records = %d, want 2", len(recsAfter))
	}
	// 被清理的文件应不存在
	files, _ := os.ReadDir(h.backupD)
	if len(files) != 2 {
		t.Errorf("backup dir has %d files, want 2", len(files))
	}
}

func TestRemoteFilesList(t *testing.T) {
	h := newHarness(t, "admin")
	h.rc.listResult = []string{"a.tar.gz", "b.tar.gz"}
	r := h.router()
	rrec := do(t, r, "POST", "/remotes", `{"name":"s3","type":"s3"}`, nil)
	var rem Remote
	json.Unmarshal(rrec.Body.Bytes(), &rem)
	rec := do(t, r, "GET", "/remotes/"+itoa(rem.ID)+"/files", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("remote files = %d", rec.Code)
	}
	var files []string
	json.Unmarshal(rec.Body.Bytes(), &files)
	if len(files) != 2 {
		t.Errorf("remote files = %v", files)
	}
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }
