package appstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeProjectDirWithinBase(t *testing.T) {
	base := t.TempDir()
	got, err := safeProjectDir(base, "wordpress-1")
	if err != nil {
		t.Fatalf("safeProjectDir: %v", err)
	}
	if want := filepath.Join(base, "wordpress-1"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSafeProjectDirRejectsInvalidName(t *testing.T) {
	base := t.TempDir()
	if _, err := safeProjectDir(base, "../escape"); err == nil {
		t.Fatal("expected invalid instance name to be rejected")
	}
}

// SafeJoin 的软链防护:base 下的实例名是指向 base 外的符号链接时,必须拒绝
// (自制 prefix 检查会跟随软链把 compose 项目写到 base 外)。
func TestSafeProjectDirRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(base, "evil-app")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := safeProjectDir(base, "evil-app"); err == nil {
		t.Fatal("symlink escaping base must be rejected")
	}
}
