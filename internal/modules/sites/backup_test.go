package sites

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- realArchiver round-trip against t.TempDir() ---

func TestRealArchiverRoundTrip(t *testing.T) {
	src := t.TempDir()
	files := map[string]string{
		"index.html":        "<h1>home</h1>",
		"css/site.css":      "body{}",
		"deep/a/b/note.txt": "hello world",
	}
	for rel, content := range files {
		full := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	arc := &realArchiver{}
	dest := filepath.Join(t.TempDir(), "site-1.tar.gz")
	size, err := arc.Pack(src, dest)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if size <= 0 {
		t.Fatalf("Pack size = %d, want > 0", size)
	}
	out := t.TempDir()
	if err := arc.Unpack(dest, out); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(out, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
}

// writeTarGz 在测试内手造一个 tar.gz,entries 为 name->content;name 以 "@symlink:" 前缀表示软链。
func writeTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range entries {
		if strings.HasPrefix(name, "@symlink:") {
			real := strings.TrimPrefix(name, "@symlink:")
			hdr := &tar.Header{Name: real, Typeflag: tar.TypeSymlink, Linkname: content, Mode: 0o777}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
			continue
		}
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRealArchiverRejectsZipSlip(t *testing.T) {
	arc := &realArchiver{}
	cases := []struct {
		name    string
		entries map[string]string
	}{
		{"parent traversal", map[string]string{"../evil": "pwned"}},
		{"absolute path", map[string]string{"/etc/evil": "pwned"}},
		{"nested traversal", map[string]string{"a/../../evil": "pwned"}},
		{"symlink escape", map[string]string{"@symlink:link": "../../etc/evil"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			arcPath := filepath.Join(base, "mal.tar.gz")
			if err := os.WriteFile(arcPath, writeTarGz(t, c.entries), 0o644); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(base, "dest")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := arc.Unpack(arcPath, dest); err == nil {
				t.Fatalf("Unpack of %s should error", c.name)
			}
			// 逃逸目标必须不存在:base 下不得出现 evil,/etc/evil 不得被创建。
			if _, err := os.Stat(filepath.Join(base, "evil")); err == nil {
				t.Errorf("%s: escape file written to %s", c.name, filepath.Join(base, "evil"))
			}
			if _, err := os.Stat("/etc/evil"); err == nil {
				t.Errorf("%s: escape file written to /etc/evil", c.name)
			}
			if _, err := os.Stat(filepath.Join(dest, "link")); err == nil {
				t.Errorf("%s: symlink entry was created", c.name)
			}
		})
	}
}

// --- mock archiver for handler tests ---

type mockArchiver struct {
	packs     []packCall
	unpacks   []unpackCall
	opens     []string
	removes   []string
	openData  []byte
	packSize  int64
	packErr   error
	unpackErr error
}

type packCall struct{ src, dest string }
type unpackCall struct{ archive, dest string }

func newMockArchiver() *mockArchiver {
	return &mockArchiver{openData: []byte("MOCK_ARCHIVE_BYTES"), packSize: 4096}
}

func (a *mockArchiver) Pack(src, dest string) (int64, error) {
	a.packs = append(a.packs, packCall{src, dest})
	if a.packErr != nil {
		return 0, a.packErr
	}
	return a.packSize, nil
}
func (a *mockArchiver) Unpack(archive, dest string) error {
	a.unpacks = append(a.unpacks, unpackCall{archive, dest})
	return a.unpackErr
}
func (a *mockArchiver) Open(archive string) (io.ReadCloser, error) {
	a.opens = append(a.opens, archive)
	return io.NopCloser(bytes.NewReader(a.openData)), nil
}
func (a *mockArchiver) Remove(archive string) error {
	a.removes = append(a.removes, archive)
	return nil
}

func newBackupModule(t *testing.T, role string) (*Module, *mockArchiver) {
	t.Helper()
	m, _ := newTestModule(t, role, newMockNginx())
	arc := newMockArchiver()
	m.archiver = arc
	return m, arc
}

func confirm() map[string]string { return map[string]string{"X-Confirm-Danger": "1"} }

func TestCreateBackupStaticSite(t *testing.T) {
	m, arc := newBackupModule(t, "operator")
	id := seedSite(t, m)
	site := getSite(t, m, id)

	rec := do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create backup = %d (%s)", rec.Code, rec.Body.String())
	}
	var b Backup
	json.Unmarshal(rec.Body.Bytes(), &b)
	if b.ID == 0 || b.SiteID != id || b.Size != arc.packSize {
		t.Errorf("unexpected backup: %+v", b)
	}
	if len(arc.packs) != 1 || arc.packs[0].src != site.RootDir {
		t.Errorf("Pack should be called with RootDir %q, got %+v", site.RootDir, arc.packs)
	}
	// 元数据已落库
	list, _ := m.ss.listBackups(id)
	if len(list) != 1 {
		t.Errorf("backup not persisted, got %d", len(list))
	}
}

func TestCreateBackupProxySiteConflict(t *testing.T) {
	m, arc := newBackupModule(t, "operator")
	pid := seedProxy(t, m)
	rec := do(m, "POST", "/sites/"+itoa(pid)+"/backups", nil, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("proxy backup should 409, got %d", rec.Code)
	}
	if len(arc.packs) != 0 {
		t.Error("proxy backup must not pack")
	}
}

func TestCreateBackupRequiresWriter(t *testing.T) {
	m, _ := newBackupModule(t, "readonly")
	id := seedSiteAs(t, "operator")
	rec := do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly backup should 403, got %d", rec.Code)
	}
}

func TestListBackups(t *testing.T) {
	m, _ := newBackupModule(t, "operator")
	id := seedSite(t, m)
	// empty → []
	rec := do(m, "GET", "/sites/"+itoa(id)+"/backups", nil, nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list = %d %q", rec.Code, rec.Body.String())
	}
	do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	rec = do(m, "GET", "/sites/"+itoa(id)+"/backups", nil, nil)
	var list []Backup
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2", len(list))
	}
	if list[0].ID < list[1].ID {
		t.Error("backups must be newest first")
	}
}

func TestDownloadBackup(t *testing.T) {
	m, arc := newBackupModule(t, "operator")
	id := seedSite(t, m)
	rec := do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	var b Backup
	json.Unmarshal(rec.Body.Bytes(), &b)

	rec = do(m, "GET", "/sites/"+itoa(id)+"/backups/"+itoa(b.ID)+"/download", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("download = %d", rec.Code)
	}
	if rec.Body.String() != string(arc.openData) {
		t.Errorf("download body = %q", rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !contains(cd, b.Filename) {
		t.Errorf("missing Content-Disposition: %q", cd)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("Content-Type = %q", ct)
	}
}
