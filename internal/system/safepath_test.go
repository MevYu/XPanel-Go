package system

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSafeJoinWithinRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := SafeJoin(root, "a.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != filepath.Join(root, "a.txt") {
		t.Fatalf("got %q", got)
	}
}

func TestSafeJoinRootItself(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"", ".", "/"} {
		got, err := SafeJoin(root, rel)
		if err != nil {
			t.Fatalf("rel=%q err=%v", rel, err)
		}
		if got != filepath.Clean(root) {
			t.Fatalf("rel=%q got %q want %q", rel, got, root)
		}
	}
}

func TestSafeJoinNeutralizesDotDot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "sub")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// 在 root 之外放一个文件,确认任何 "../" 都不能命中它。
	secret := filepath.Join(parent, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"..", "../", "../secret", "a/../../b", "./../x", "../../../../etc/passwd"} {
		got, err := SafeJoin(root, rel)
		if err != nil {
			t.Errorf("rel=%q unexpected err %v", rel, err)
			continue
		}
		// "../" 被中和,结果必须仍限定在 root 子树内,绝不等于 root 外的 secret。
		if !withinRoot(filepath.Clean(root), got) {
			t.Errorf("rel=%q escaped root: %q", rel, got)
		}
		if got == secret {
			t.Errorf("rel=%q reached outside secret", rel)
		}
	}
}

func TestSafeJoinRejectsAbsoluteEscape(t *testing.T) {
	root := t.TempDir()
	// 绝对路径被当作 root 下的相对路径,不能命中真实 /etc/passwd。
	got, err := SafeJoin(root, "/etc/passwd")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got != filepath.Join(root, "etc/passwd") {
		t.Fatalf("absolute path not confined: %q", got)
	}
}

func TestSafeJoinRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// root/link -> outside
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := SafeJoin(root, "link/secret"); err != ErrPathEscape {
		t.Errorf("symlink escape want ErrPathEscape, got %v", err)
	}
}

func TestSafeJoinAllowsInternalSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := SafeJoin(root, "link/f"); err != nil {
		t.Errorf("internal symlink should be allowed, got %v", err)
	}
}

func TestSafeJoinNonexistentChildAllowed(t *testing.T) {
	root := t.TempDir()
	// 尚不存在的文件(待写入)其父目录在 root 内 → 允许。
	got, err := SafeJoin(root, "newdir/newfile.txt")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got != filepath.Join(root, "newdir/newfile.txt") {
		t.Fatalf("got %q", got)
	}
}
