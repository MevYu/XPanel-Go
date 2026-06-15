package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveExtractRoundTrip(t *testing.T) {
	srcRoot := t.TempDir()
	// 构造 srcRoot/site/{a.txt, sub/b.txt}
	mustWrite(t, filepath.Join(srcRoot, "site", "a.txt"), "hello")
	mustWrite(t, filepath.Join(srcRoot, "site", "sub", "b.txt"), "world")

	dest := filepath.Join(t.TempDir(), "out.tar.gz")
	a := tarArchiver{}
	size, err := a.archive(srcRoot, "site", dest)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if size <= 0 {
		t.Errorf("archive size = %d", size)
	}

	restoreRoot := t.TempDir()
	if err := a.extract(dest, restoreRoot); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got := readFile(t, filepath.Join(restoreRoot, "site", "a.txt")); got != "hello" {
		t.Errorf("a.txt = %q", got)
	}
	if got := readFile(t, filepath.Join(restoreRoot, "site", "sub", "b.txt")); got != "world" {
		t.Errorf("b.txt = %q", got)
	}
}

func TestArchiveRejectsTraversalSource(t *testing.T) {
	srcRoot := t.TempDir()
	dest := filepath.Join(t.TempDir(), "out.tar.gz")
	a := tarArchiver{}
	_, err := a.archive(srcRoot, "../../etc", dest)
	if err == nil {
		t.Fatal("archive with ../ rel should be rejected")
	}
}

func TestExtractRejectsTraversalEntry(t *testing.T) {
	// 手工造一个含 "../evil" 成员的 tar.gz,extract 必须拒绝写到根外。
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("pwned")
	hdr := &tar.Header{Name: "../evil.txt", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()
	gz.Close()

	archive := filepath.Join(t.TempDir(), "evil.tar.gz")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	parent := t.TempDir()
	destRoot := filepath.Join(parent, "restore")
	// SafeJoin 把 "../evil.txt" 中和为 destRoot 内路径(不逃逸),解包应成功且不写到根外。
	a := tarArchiver{}
	if err := a.extract(archive, destRoot); err != nil {
		t.Fatalf("extract: %v", err)
	}
	// 关键:绝不写到 destRoot 之外
	if _, statErr := os.Stat(filepath.Join(parent, "evil.txt")); statErr == nil {
		t.Fatal("traversal entry escaped destination root")
	}
	// 中和后的文件应落在 destRoot 内
	if _, statErr := os.Stat(filepath.Join(destRoot, "evil.txt")); statErr != nil {
		t.Fatalf("neutralized entry should land inside root: %v", statErr)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
