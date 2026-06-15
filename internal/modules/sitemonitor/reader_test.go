package sitemonitor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/system"
)

func TestFileLogReaderTailLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	var content []byte
	for i := 0; i < 100; i++ {
		content = append(content, []byte("line"+strconv.Itoa(i)+"\n")...)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := FileLogReader{}.TailLines(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 10 {
		t.Fatalf("expected 10 tail lines, got %d", len(lines))
	}
	if lines[0] != "line90" || lines[9] != "line99" {
		t.Errorf("tail order wrong: %q .. %q", lines[0], lines[9])
	}
}

func TestFileLogReaderUnderLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.log")
	if err := os.WriteFile(path, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := FileLogReader{}.TailLines(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || lines[0] != "a" || lines[2] != "c" {
		t.Errorf("lines = %+v", lines)
	}
}

func TestResolveLogPathTraversalBlocked(t *testing.T) {
	root := t.TempDir()
	s := Settings{LogRoot: root, AccessLog: filepath.Join(root, "access.log")}

	// 默认路径(空 rel)解析成功。
	if _, err := resolveLogPath(s, ""); err != nil {
		t.Fatalf("default path should resolve: %v", err)
	}

	// ../ 穿越被 SafeJoin 中和到 root 子树内(不逃逸,也不报错;后续读文件会因不存在而失败)。
	got, err := resolveLogPath(s, "../../etc/passwd")
	if err != nil {
		t.Errorf("traversal should be neutralized, got %v", err)
	}
	if !strings.HasPrefix(got, root) {
		t.Errorf("traversal escaped root: %q", got)
	}

	// 指向 root 外的符号链接被拒(真正的逃逸向量)。
	link := filepath.Join(root, "evil")
	if err := os.Symlink("/etc", link); err == nil {
		if _, err := resolveLogPath(s, "evil/passwd"); err != system.ErrPathEscape {
			t.Errorf("symlink escape should be ErrPathEscape, got %v", err)
		}
	}

	// root 内的合法子路径放行。
	sub := filepath.Join(root, "sub.log")
	if err := os.WriteFile(sub, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = resolveLogPath(s, "sub.log")
	if err != nil {
		t.Fatalf("legit subpath should resolve: %v", err)
	}
	if got != sub {
		t.Errorf("resolved = %q want %q", got, sub)
	}
}

func TestSettingsValidate(t *testing.T) {
	good := DefaultSettings()
	if err := good.Validate(); err != nil {
		t.Errorf("default settings should validate: %v", err)
	}
	bad := []Settings{
		{LogRoot: "relative/path", AccessLog: "/a"},
		{LogRoot: "/root/../x", AccessLog: "/a"},
		{LogRoot: "/ok", AccessLog: ""},
		{LogRoot: "/ok", AccessLog: "/a", MaxLines: -1},
	}
	for i, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("bad settings[%d] should fail validation: %+v", i, s)
		}
	}
}
