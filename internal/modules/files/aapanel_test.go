package files

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// newModuleAt builds a module rooted at a fixed dir (shared across calls) for tests
// that need the same root with different roles or a fresh store.
func newModuleAt(t *testing.T, root, role string) (*Module, string, *[]auditRec) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var audits []auditRec
	m, err := New(root, st, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit: func(uid *int64, action, detail, ip string) {
			audits = append(audits, auditRec{uid, action, detail, ip})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, root, &audits
}

func req(t *testing.T, r http.Handler, method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	hr := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdr {
		hr.Header.Set(k, v)
	}
	r.ServeHTTP(rec, hr)
	return rec
}

// ---- list owner/group ----

func TestListReturnsOwnerGroup(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)
	rec := req(t, r, "GET", "/list?path=", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list want 200, got %d", rec.Code)
	}
	var out []dirEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 entry, got %d", len(out))
	}
	if out[0].Owner == "" || out[0].Group == "" {
		t.Fatalf("owner/group must be populated, got owner=%q group=%q", out[0].Owner, out[0].Group)
	}
}

// ---- chown ----

func TestChownRequiresAdmin(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)
	body, _ := json.Marshal(chownReq{Path: "f", Owner: "root"})
	rec := req(t, r, "POST", "/chown", string(body), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator chown want 403, got %d", rec.Code)
	}
}

func TestChownRejectsInvalidName(t *testing.T) {
	m, root, _ := newModule(t, "admin")
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	m.chown = func([]string) error { called = true; return nil }
	m.lookupUser = func(n string) (string, error) { return n, nil }
	r := panelRouter(m)
	for _, bad := range []string{"root; rm -rf /", "a b", "$(id)", strings.Repeat("a", 33), "../x"} {
		body, _ := json.Marshal(chownReq{Path: "f", Owner: bad})
		rec := req(t, r, "POST", "/chown", string(body), nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("chown owner %q want 400, got %d", bad, rec.Code)
		}
	}
	if called {
		t.Fatal("chown executor must not run for invalid names")
	}
}

func TestChownRejectsMissingUser(t *testing.T) {
	m, root, _ := newModule(t, "admin")
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.chown = func([]string) error { return nil }
	m.lookupUser = func(string) (string, error) { return "", os.ErrNotExist }
	r := panelRouter(m)
	body, _ := json.Marshal(chownReq{Path: "f", Owner: "ghost"})
	rec := req(t, r, "POST", "/chown", string(body), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("nonexistent owner want 400, got %d", rec.Code)
	}
}

func TestChownSuccessAuditsAndUsesArgArray(t *testing.T) {
	m, root, audits := newModule(t, "admin")
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var gotArgs []string
	m.chown = func(args []string) error { gotArgs = args; return nil }
	m.lookupUser = func(n string) (string, error) { return n, nil }
	m.lookupGroup = func(n string) (string, error) { return n, nil }
	r := panelRouter(m)
	body, _ := json.Marshal(chownReq{Path: "f", Owner: "www", Group: "www"})
	rec := req(t, r, "POST", "/chown", string(body), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("chown want 204, got %d (%s)", rec.Code, rec.Body)
	}
	if len(gotArgs) != 2 || gotArgs[0] != "www:www" {
		t.Fatalf("chown args = %v, want [www:www <abs>]", gotArgs)
	}
	if !strings.HasPrefix(gotArgs[1], root) {
		t.Fatalf("chown target %q not within root", gotArgs[1])
	}
	if len(*audits) != 1 || (*audits)[0].action != "files.chown" {
		t.Fatalf("want one files.chown audit, got %+v", *audits)
	}
}

func TestChownPathTraversalRejected(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	m, _, _ := newModuleAt(t, root, "admin")
	called := false
	m.chown = func([]string) error { called = true; return nil }
	m.lookupUser = func(n string) (string, error) { return n, nil }
	r := panelRouter(m)
	if err := os.WriteFile(filepath.Join(parent, "outside"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent, filepath.Join(root, "esc")); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(chownReq{Path: "esc/outside", Owner: "root"})
	rec := req(t, r, "POST", "/chown", string(body), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("chown symlink escape want 403, got %d", rec.Code)
	}
	if called {
		t.Fatal("chown must not run on escaped path")
	}
}

// ---- trash ----

func TestDeleteSoftDeletesToTrash(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "doomed.txt"), []byte("bye"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)
	rec := req(t, r, "POST", "/delete?path=doomed.txt", "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete want 204, got %d (%s)", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(root, "doomed.txt")); !os.IsNotExist(err) {
		t.Fatal("file should be gone from original location")
	}
	// trash list shows it
	rec = req(t, r, "GET", "/trash", "", nil)
	var items []trashItem
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].OrigPath != "doomed.txt" {
		t.Fatalf("trash list = %+v", items)
	}
}

func TestTrashRestore(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "r.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)
	req(t, r, "POST", "/delete?path=r.txt", "", nil)
	rec := req(t, r, "GET", "/trash", "", nil)
	var items []trashItem
	json.Unmarshal(rec.Body.Bytes(), &items)
	if len(items) != 1 {
		t.Fatalf("want 1 trash item, got %d", len(items))
	}
	body, _ := json.Marshal(trashRestoreReq{ID: items[0].ID})
	rec = req(t, r, "POST", "/trash/restore", string(body), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("restore want 204, got %d (%s)", rec.Code, rec.Body)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "r.txt")); string(b) != "data" {
		t.Fatalf("restored content = %q", b)
	}
	rec = req(t, r, "GET", "/trash", "", nil)
	json.Unmarshal(rec.Body.Bytes(), &items)
	if len(items) != 0 {
		t.Fatalf("trash should be empty after restore, got %d", len(items))
	}
}

func TestTrashEmptyRequiresAdminAndConfirm(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)
	req(t, r, "POST", "/delete?path=x.txt", "", nil)

	// no confirm header -> 428
	rec := req(t, r, "POST", "/trash/empty", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("empty without confirm want 428, got %d", rec.Code)
	}
	// confirm but operator -> 403
	rec = req(t, r, "POST", "/trash/empty", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator empty want 403, got %d", rec.Code)
	}

	// admin + confirm -> 204, trash cleared
	ma, _, _ := newModuleAt(t, root, "admin")
	ra := panelRouter(ma)
	rec = req(t, ra, "POST", "/trash/empty", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin empty want 204, got %d (%s)", rec.Code, rec.Body)
	}
	rec = req(t, ra, "GET", "/trash", "", nil)
	var items []trashItem
	json.Unmarshal(rec.Body.Bytes(), &items)
	if len(items) != 0 {
		t.Fatalf("trash not cleared, got %d", len(items))
	}
}

// ---- move ----

func TestMove(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "src.txt"), []byte("m"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)
	body, _ := json.Marshal(moveReq{Src: "src.txt", Dest: "sub/dst.txt"})
	rec := req(t, r, "POST", "/move", string(body), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("move want 204, got %d (%s)", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(root, "src.txt")); !os.IsNotExist(err) {
		t.Fatal("src should be gone")
	}
	if b, _ := os.ReadFile(filepath.Join(root, "sub", "dst.txt")); string(b) != "m" {
		t.Fatalf("moved content = %q", b)
	}
}

func TestMoveRejectsExistingDest(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	os.WriteFile(filepath.Join(root, "a"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(root, "b"), []byte("b"), 0o644)
	r := panelRouter(m)
	body, _ := json.Marshal(moveReq{Src: "a", Dest: "b"})
	rec := req(t, r, "POST", "/move", string(body), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("move onto existing want 409, got %d", rec.Code)
	}
}

func TestMovePathTraversalRejected(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	os.MkdirAll(root, 0o755)
	m, _, _ := newModuleAt(t, root, "operator")
	os.WriteFile(filepath.Join(root, "a"), []byte("a"), 0o644)
	r := panelRouter(m)
	body, _ := json.Marshal(moveReq{Src: "a", Dest: "../escaped"})
	rec := req(t, r, "POST", "/move", string(body), nil)
	if _, err := os.Stat(filepath.Join(parent, "escaped")); err == nil {
		t.Fatal("move escaped root")
	}
	if rec.Code == http.StatusNoContent {
		// dest got clamped inside root, fine; just ensure nothing escaped (checked above)
	}
}

// ---- dirsize ----

func TestDirSize(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	os.MkdirAll(filepath.Join(root, "d"), 0o755)
	os.WriteFile(filepath.Join(root, "d", "a"), bytes.Repeat([]byte("x"), 100), 0o644)
	os.WriteFile(filepath.Join(root, "d", "b"), bytes.Repeat([]byte("y"), 50), 0o644)
	r := panelRouter(m)
	rec := req(t, r, "GET", "/dirsize?path=d", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("dirsize want 200, got %d", rec.Code)
	}
	var resp dirSizeResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Bytes != 150 || resp.Files != 2 {
		t.Fatalf("dirsize = %+v, want 150 bytes / 2 files", resp)
	}
}

func TestDirSizeSkipsSymlinks(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "big"), bytes.Repeat([]byte("x"), 1000), 0o644)
	os.MkdirAll(filepath.Join(root, "d"), 0o755)
	os.WriteFile(filepath.Join(root, "d", "real"), []byte("ab"), 0o644)
	os.Symlink(filepath.Join(outside, "big"), filepath.Join(root, "d", "link"))
	r := panelRouter(m)
	rec := req(t, r, "GET", "/dirsize?path=d", "", nil)
	var resp dirSizeResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Bytes != 2 {
		t.Fatalf("dirsize should skip symlink, got %d bytes", resp.Bytes)
	}
}

// ---- search ----

func TestSearchByName(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	os.WriteFile(filepath.Join(root, "alpha.go"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(root, "beta.txt"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.WriteFile(filepath.Join(root, "sub", "gamma.go"), []byte("x"), 0o644)
	r := panelRouter(m)
	rec := req(t, r, "GET", "/search?path=&name=*.go", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("search want 200, got %d", rec.Code)
	}
	var res []string
	json.Unmarshal(rec.Body.Bytes(), &res)
	if len(res) != 2 {
		t.Fatalf("name search = %v, want 2 .go files", res)
	}
}

func TestSearchByContent(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello NEEDLE here"), 0o644)
	os.WriteFile(filepath.Join(root, "b.txt"), []byte("nothing"), 0o644)
	r := panelRouter(m)
	rec := req(t, r, "GET", "/search?path=&content=NEEDLE", "", nil)
	var res []string
	json.Unmarshal(rec.Body.Bytes(), &res)
	if len(res) != 1 || res[0] != "a.txt" {
		t.Fatalf("content search = %v, want [a.txt]", res)
	}
}

func TestSearchDoesNotFollowSymlinkOutOfRoot(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.go"), []byte("NEEDLE"), 0o644)
	os.Symlink(outside, filepath.Join(root, "link"))
	r := panelRouter(m)
	rec := req(t, r, "GET", "/search?path=&name=*.go", "", nil)
	var res []string
	json.Unmarshal(rec.Body.Bytes(), &res)
	for _, p := range res {
		if strings.Contains(p, "secret") {
			t.Fatalf("search followed symlink out of root: %v", res)
		}
	}
}

// ---- remote download (SSRF) ----

var dangerHdr = map[string]string{"X-Confirm-Danger": "yes"}

func TestRemoteDownloadBlocksPrivateIP(t *testing.T) {
	// 用真实 SSRF transport,目标解析到回环/私网必须被拒,且零数据落盘。
	m, root, _ := newModule(t, "admin")
	r := panelRouter(m)
	for _, target := range []string{
		"http://127.0.0.1/x",
		"http://localhost/x",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/x",
		"http://192.168.1.1/x",
		"http://[::1]/x",
		"ftp://example.com/x",
	} {
		body, _ := json.Marshal(remoteDownloadReq{URL: target, Dest: "", Name: "out"})
		rec := req(t, r, "POST", "/remote-download", string(body), dangerHdr)
		if rec.Code == http.StatusNoContent {
			t.Fatalf("SSRF target %q must be rejected, got 204", target)
		}
		if _, err := os.Stat(filepath.Join(root, "out")); err == nil {
			t.Fatalf("SSRF target %q wrote a file", target)
		}
	}
}

func TestRemoteDownloadSuccess(t *testing.T) {
	m, root, audits := newModule(t, "admin")
	// 注入 mock fetcher,零真实网络。
	m.httpGet = func(string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("payload")),
		}, nil
	}
	r := panelRouter(m)
	body, _ := json.Marshal(remoteDownloadReq{URL: "https://example.com/file.bin", Dest: "dl"})
	rec := req(t, r, "POST", "/remote-download", string(body), dangerHdr)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("remote download want 204, got %d (%s)", rec.Code, rec.Body)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "dl", "file.bin")); string(b) != "payload" {
		t.Fatalf("downloaded content = %q", b)
	}
	found := false
	for _, a := range *audits {
		if a.action == "files.remote_download" {
			found = true
		}
	}
	if !found {
		t.Fatal("remote download must audit")
	}
}

func TestRemoteDownloadRejectsNonHTTP(t *testing.T) {
	m, _, _ := newModule(t, "admin")
	m.httpGet = func(string) (*http.Response, error) { t.Fatal("must not fetch"); return nil, nil }
	r := panelRouter(m)
	body, _ := json.Marshal(remoteDownloadReq{URL: "file:///etc/passwd", Dest: "", Name: "x"})
	rec := req(t, r, "POST", "/remote-download", string(body), dangerHdr)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-http url want 400, got %d", rec.Code)
	}
}

func TestRemoteDownloadRequiresAdminAndConfirm(t *testing.T) {
	m, _, _ := newModule(t, "operator")
	m.httpGet = func(string) (*http.Response, error) { t.Fatal("must not fetch"); return nil, nil }
	r := panelRouter(m)
	body, _ := json.Marshal(remoteDownloadReq{URL: "https://example.com/x", Dest: "", Name: "x"})
	// missing confirm -> 428
	rec := req(t, r, "POST", "/remote-download", string(body), nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("remote download without confirm want 428, got %d", rec.Code)
	}
	// operator with confirm -> 403
	rec = req(t, r, "POST", "/remote-download", string(body), dangerHdr)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator remote download want 403, got %d", rec.Code)
	}
}

// isBlockedIP unit coverage for the address blocklist.
func TestIsBlockedIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "169.254.169.254", "10.1.2.3", "192.168.0.1", "172.16.0.1", "0.0.0.0", "100.64.1.1", "224.0.0.1"}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}
