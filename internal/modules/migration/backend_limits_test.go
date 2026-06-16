package migration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// craftSitePkg 构造含 manifest + 一组 site/ 成员的迁移包,成员按给定顺序写入。
func craftSitePkg(t *testing.T, names []string, body []byte) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	mani := []byte(`{"name":"n"}`)
	_ = tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(mani)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(mani)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
	}
	tw.Close()
	gz.Close()
	f := filepath.Join(t.TempDir(), "limits.tar.gz")
	if err := os.WriteFile(f, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestUnpackAbortsOnByteBudget(t *testing.T) {
	old := maxUnpackBytes
	maxUnpackBytes = 1024
	t.Cleanup(func() { maxUnpackBytes = old })

	// 单个成员就超出预算 -> errUnpackTooLarge,且不把全部内容落盘。
	body := bytes.Repeat([]byte("A"), 4096)
	pkg := craftSitePkg(t, []string{"site/big.bin"}, body)
	siteDest := t.TempDir()
	if _, err := (tarPacker{}).unpack(pkg, siteDest, ""); err != errUnpackTooLarge {
		t.Fatalf("expected errUnpackTooLarge, got %v", err)
	}
	// 写出的文件不得超过预算+1(LimitReader 截断),绝不写爆磁盘。
	if fi, err := os.Stat(filepath.Join(siteDest, "big.bin")); err == nil && fi.Size() > maxUnpackBytes+1 {
		t.Fatalf("wrote %d bytes, exceeds clamp", fi.Size())
	}
}

func TestUnpackAbortsOnCumulativeBytes(t *testing.T) {
	old := maxUnpackBytes
	maxUnpackBytes = 2048
	t.Cleanup(func() { maxUnpackBytes = old })

	// 多个各自合规的成员,累计超预算 -> 中止。
	body := bytes.Repeat([]byte("B"), 1024)
	pkg := craftSitePkg(t, []string{"site/a", "site/b", "site/c"}, body)
	if _, err := (tarPacker{}).unpack(pkg, t.TempDir(), ""); err != errUnpackTooLarge {
		t.Fatalf("expected errUnpackTooLarge on cumulative overflow, got %v", err)
	}
}

func TestUnpackAbortsOnEntryCount(t *testing.T) {
	old := maxUnpackEntries
	maxUnpackEntries = 10
	t.Cleanup(func() { maxUnpackEntries = old })

	names := make([]string, 50)
	for i := range names {
		names[i] = "site/f" + itoa(int64(i))
	}
	pkg := craftSitePkg(t, names, []byte("x"))
	if _, err := (tarPacker{}).unpack(pkg, t.TempDir(), ""); err != errUnpackTooLarge {
		t.Fatalf("expected errUnpackTooLarge on entry-count overflow, got %v", err)
	}
}

func TestUnpackWithinLimitsSucceeds(t *testing.T) {
	// 合规包(成员数与总字节都在上限内)正常解包。
	body := []byte("hello")
	pkg := craftSitePkg(t, []string{"site/a.txt", "site/b.txt"}, body)
	siteDest := t.TempDir()
	if _, err := (tarPacker{}).unpack(pkg, siteDest, ""); err != nil {
		t.Fatalf("unpack within limits: %v", err)
	}
	if got := readFile(t, filepath.Join(siteDest, "a.txt")); got != "hello" {
		t.Fatalf("a.txt = %q", got)
	}
}
