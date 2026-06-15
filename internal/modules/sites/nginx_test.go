package sites

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRealNginxWriteRemove(t *testing.T) {
	dir := t.TempDir()
	n := newRealNginx(dir)
	if err := n.WriteConfig("example.com", "server {}\n"); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	p := filepath.Join(dir, "example.com.conf")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	if string(b) != "server {}\n" {
		t.Errorf("config content = %q", b)
	}
	// 没有 .tmp 残留
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file %q", e.Name())
		}
	}
	if err := n.RemoveConfig("example.com"); err != nil {
		t.Fatalf("RemoveConfig: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("config should be removed")
	}
	// 重复删除不报错
	if err := n.RemoveConfig("example.com"); err != nil {
		t.Errorf("removing missing config should be nil, got %v", err)
	}
}

func TestRealNginxRejectsBadName(t *testing.T) {
	n := newRealNginx(t.TempDir())
	for _, bad := range []string{"../escape", "a/b", "..", "bad name"} {
		if err := n.WriteConfig(bad, "x"); err == nil {
			t.Errorf("WriteConfig(%q) should reject", bad)
		}
	}
}
