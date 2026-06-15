package antitamper

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanTreeFingerprints(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "hello")
	writeFile(t, filepath.Join(root, "sub", "b.txt"), "world")

	states, err := ScanTree(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 {
		t.Fatalf("want 2 files, got %d", len(states))
	}
	a := states[filepath.Join(root, "a.txt")]
	if a.Hash == "" || a.Mode == 0 {
		t.Fatalf("incomplete state: %+v", a)
	}
}

func TestScanTreeExcludes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "keep.txt"), "x")
	writeFile(t, filepath.Join(root, "cache", "junk.log"), "y")
	writeFile(t, filepath.Join(root, "z.log"), "z")

	states, err := ScanTree(context.Background(), root, []string{"cache", "*.log"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := states[filepath.Join(root, "keep.txt")]; !ok {
		t.Fatal("keep.txt should be present")
	}
	if len(states) != 1 {
		t.Fatalf("excludes failed, got %d files: %+v", len(states), states)
	}
}

func TestScanTreeSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "real.txt"), "data")
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(filepath.Join(root, "real.txt"), link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	states, err := ScanTree(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := states[link]; ok {
		t.Fatal("symlink must not be fingerprinted")
	}
}

func TestDiffDetectsAllChangeTypes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "keep.txt"), "same")
	writeFile(t, filepath.Join(root, "mod.txt"), "before")
	writeFile(t, filepath.Join(root, "del.txt"), "gone soon")

	base, err := ScanTree(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}

	// mutate: modify, delete, add
	writeFile(t, filepath.Join(root, "mod.txt"), "AFTER")
	if err := os.Remove(filepath.Join(root, "del.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "new.txt"), "fresh")

	cur, err := ScanTree(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}

	changes := Diff(base, cur)
	got := map[ChangeType]string{}
	for _, c := range changes {
		got[c.Type] = filepath.Base(c.Path)
	}
	if got[ChangeModified] != "mod.txt" {
		t.Errorf("modified not detected: %+v", changes)
	}
	if got[ChangeDeleted] != "del.txt" {
		t.Errorf("deleted not detected: %+v", changes)
	}
	if got[ChangeAdded] != "new.txt" {
		t.Errorf("added not detected: %+v", changes)
	}
	if len(changes) != 3 {
		t.Fatalf("want exactly 3 changes, got %d: %+v", len(changes), changes)
	}
}

func TestDiffNoChanges(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "x")
	base, _ := ScanTree(context.Background(), root, nil)
	cur, _ := ScanTree(context.Background(), root, nil)
	if c := Diff(base, cur); len(c) != 0 {
		t.Fatalf("stable tree must yield no changes, got %+v", c)
	}
}

// ctx 已取消时,ScanTree 在文件间立即 bail,不扫完整棵树。
// 这是 Stop()(cancel+<-done)能快速返回的前提:慢扫描不会冻结持锁的 Manager。
func TestScanTreeBailsOnCanceledCtx(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 200; i++ {
		writeFile(t, filepath.Join(root, "f"+itoa(i)+".txt"), "data")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanTree(ctx, root, nil)
	if err != context.Canceled {
		t.Fatalf("ScanTree on canceled ctx = %v, want context.Canceled", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
