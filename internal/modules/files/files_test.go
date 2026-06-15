package files

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

type auditRec struct {
	userID *int64
	action string
	detail string
	ip     string
}

func newModule(t *testing.T, role string) (*Module, string, *[]auditRec) {
	t.Helper()
	root := t.TempDir()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var audits []auditRec
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit: func(uid *int64, action, detail, ip string) {
			audits = append(audits, auditRec{uid, action, detail, ip})
		},
	}
	m, err := New(root, st, deps)
	if err != nil {
		t.Fatal(err)
	}
	return m, root, &audits
}

func panelRouter(m *Module) chi.Router {
	r := chi.NewRouter()
	m.Routes(r)
	return r
}

func TestMetaSwitchable(t *testing.T) {
	m, _, _ := newModule(t, "admin")
	if m.Meta().ID != "files" || m.Meta().AlwaysOn {
		t.Errorf("files must be id=files, not AlwaysOn, got %+v", m.Meta())
	}
}

func TestWriteRequiresOperator(t *testing.T) {
	m, _, audits := newModule(t, "readonly")
	r := panelRouter(m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/write?path=x.txt", strings.NewReader("data"))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly write want 403, got %d", rec.Code)
	}
	if len(*audits) != 0 {
		t.Fatalf("forbidden write must not audit, got %d", len(*audits))
	}
}

func TestWriteAndReadRoundtrip(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	r := panelRouter(m)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/write?path=hello.txt", strings.NewReader("hi"))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("write want 204, got %d (%s)", rec.Code, rec.Body)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "hello.txt")); string(b) != "hi" {
		t.Fatalf("file content = %q", b)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/read?path=hello.txt", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "hi" {
		t.Fatalf("read got %d %q", rec.Code, rec.Body)
	}
}

func TestPanelPathTraversalConfined(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	m, err := New(root, st, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, "operator" },
		Audit:     func(*int64, string, string, string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)

	// "../escaped" 被中和:必须写进 root 内,绝不写到 parent。
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/write?path=../escaped", strings.NewReader("x")))
	if _, err := os.Stat(filepath.Join(parent, "escaped")); err == nil {
		t.Fatal("traversal escaped root: file written outside")
	}
}

func TestPanelSymlinkEscapeRejected(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("top"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/read?path=link/secret", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("symlink escape read want 403, got %d (%s)", rec.Code, rec.Body)
	}
}

func TestChmodRequiresOperatorAndAudits(t *testing.T) {
	m, root, audits := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)
	body, _ := json.Marshal(chmodReq{Path: "f", Mode: "0640"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/chmod", bytes.NewReader(body))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("chmod want 204, got %d (%s)", rec.Code, rec.Body)
	}
	fi, _ := os.Stat(filepath.Join(root, "f"))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
	if len(*audits) != 1 || (*audits)[0].action != "files.chmod" {
		t.Fatalf("expected one chmod audit, got %+v", *audits)
	}
}

func TestCompressExtractRoundtrip(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("aaa"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := panelRouter(m)

	body, _ := json.Marshal(compressReq{Paths: []string{"a.txt"}, Dest: "arc.zip"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/compress", bytes.NewReader(body)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("compress want 204, got %d (%s)", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(root, "arc.zip")); err != nil {
		t.Fatalf("zip not created: %v", err)
	}

	body, _ = json.Marshal(extractReq{Path: "arc.zip", Dest: "out"})
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/extract", bytes.NewReader(body)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("extract want 204, got %d (%s)", rec.Code, rec.Body)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "out", "a.txt")); string(b) != "aaa" {
		t.Fatalf("extracted content = %q", b)
	}
}
