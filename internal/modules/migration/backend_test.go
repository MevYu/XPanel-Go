package migration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

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

func TestPackUnpackRoundTrip(t *testing.T) {
	siteRoot := t.TempDir()
	mustWrite(t, filepath.Join(siteRoot, "index.php"), "<?php")
	mustWrite(t, filepath.Join(siteRoot, "sub", "app.js"), "console.log(1)")

	dbDump := filepath.Join(t.TempDir(), "db.sql")
	mustWrite(t, dbDump, "CREATE DATABASE x;")

	pkgFile := filepath.Join(t.TempDir(), "pkg.tar.gz")
	meta := Meta{Name: "n", Domain: "ex.com", SitePath: siteRoot, PHPVersion: "8.2", DBKind: "mysql", DBName: "x"}

	p := tarPacker{}
	size, err := p.pack(siteRoot, dbDump, meta, pkgFile)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if size <= 0 {
		t.Errorf("size = %d", size)
	}

	got, err := p.readManifest(pkgFile)
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if got.Domain != "ex.com" || got.DBKind != "mysql" || got.PHPVersion != "8.2" {
		t.Errorf("manifest mismatch: %+v", got)
	}

	siteDest := t.TempDir()
	dbDest := filepath.Join(t.TempDir(), "restore.sql")
	hasDB, err := p.unpack(pkgFile, siteDest, dbDest)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if !hasDB {
		t.Error("expected hasDB=true")
	}
	if got := readFile(t, filepath.Join(siteDest, "index.php")); got != "<?php" {
		t.Errorf("index.php = %q", got)
	}
	if got := readFile(t, filepath.Join(siteDest, "sub", "app.js")); got != "console.log(1)" {
		t.Errorf("app.js = %q", got)
	}
	if got := readFile(t, dbDest); got != "CREATE DATABASE x;" {
		t.Errorf("db restore = %q", got)
	}
}

func TestPackNoDatabase(t *testing.T) {
	siteRoot := t.TempDir()
	mustWrite(t, filepath.Join(siteRoot, "a.txt"), "hi")
	pkgFile := filepath.Join(t.TempDir(), "pkg.tar.gz")

	p := tarPacker{}
	if _, err := p.pack(siteRoot, "", Meta{Name: "n"}, pkgFile); err != nil {
		t.Fatalf("pack: %v", err)
	}
	hasDB, err := p.unpack(pkgFile, t.TempDir(), filepath.Join(t.TempDir(), "x.sql"))
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if hasDB {
		t.Error("expected hasDB=false for package without database")
	}
}

func TestReadManifestRejectsNonPackage(t *testing.T) {
	// 合法 tar.gz 但无 manifest 成员 -> errNoManifest。
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("x")
	_ = tw.WriteHeader(&tar.Header{Name: "site/a.txt", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	tw.Close()
	gz.Close()

	f := filepath.Join(t.TempDir(), "nomani.tar.gz")
	if err := os.WriteFile(f, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (tarPacker{}).readManifest(f); err != errNoManifest {
		t.Fatalf("expected errNoManifest, got %v", err)
	}
}

// craftPkg 手工构造含给定成员的迁移包(始终含 manifest)。
func craftPkg(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name, content string) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(content))
	}
	write(manifestName, `{"name":"n"}`)
	for name, content := range entries {
		write(name, content)
	}
	tw.Close()
	gz.Close()
	f := filepath.Join(t.TempDir(), "crafted.tar.gz")
	if err := os.WriteFile(f, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestUnpackTarSlipSiteEntryNeutralized(t *testing.T) {
	// site/ 前缀但 rel 含 ../ 试图逃出 siteDest。SafeJoin 中和(clamp)到根内,
	// 关键保证:绝不写到 siteDest 之外。
	parent := t.TempDir()
	siteDest := filepath.Join(parent, "site")
	pkg := craftPkg(t, map[string]string{"site/../../evil.txt": "pwned"})
	if _, err := (tarPacker{}).unpack(pkg, siteDest, ""); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "evil.txt")); err == nil {
		t.Fatal("tar slip escaped siteDest")
	}
	if _, err := os.Stat(filepath.Join(siteDest, "evil.txt")); err != nil {
		t.Fatalf("neutralized entry should land inside siteDest: %v", err)
	}
}

func TestUnpackBareTraversalEntryNeutralized(t *testing.T) {
	// 无 site/ 前缀的裸 ../ 成员:default 分支经 SafeJoin 校验,中和到根内,绝不逃逸,且不落盘。
	parent := t.TempDir()
	siteDest := filepath.Join(parent, "site")
	pkg := craftPkg(t, map[string]string{"../evil.txt": "pwned"})
	if _, err := (tarPacker{}).unpack(pkg, siteDest, ""); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "evil.txt")); err == nil {
		t.Fatal("bare traversal entry escaped siteDest")
	}
}

func TestUnpackRejectsSymlinkEscape(t *testing.T) {
	// siteDest 内预置一个指向根外的符号链接目录;tar 成员试图穿它写文件 -> SafeJoin 拒绝。
	parent := t.TempDir()
	siteDest := filepath.Join(parent, "site")
	if err := os.MkdirAll(siteDest, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(siteDest, "link")); err != nil {
		t.Fatal(err)
	}
	pkg := craftPkg(t, map[string]string{"site/link/evil.txt": "pwned"})
	if _, err := (tarPacker{}).unpack(pkg, siteDest, ""); err != errUnsafeEntry {
		t.Fatalf("expected errUnsafeEntry on symlink escape, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "evil.txt")); err == nil {
		t.Fatal("symlink escape wrote file outside root")
	}
}

func TestUnpackSkipsUnknownTopLevelEntry(t *testing.T) {
	// 既非 site/ 也非 database.sql 的安全成员(无穿越)被跳过,不报错也不写盘。
	pkg := craftPkg(t, map[string]string{"readme.md": "x"})
	siteDest := t.TempDir()
	if _, err := (tarPacker{}).unpack(pkg, siteDest, ""); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err := os.Stat(filepath.Join(siteDest, "readme.md")); err == nil {
		t.Fatal("unknown top-level entry should not be written")
	}
}
