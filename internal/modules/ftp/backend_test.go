package ftp

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakePurePW 写一个把每个 argv 各一行落盘的脚本,返回脚本路径与录制文件路径。
func fakePurePW(t *testing.T) (script, recFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake not supported on windows")
	}
	dir := t.TempDir()
	recFile = filepath.Join(dir, "argv")
	script = filepath.Join(dir, "pure-pw")
	// 逐个参数打印(含空参数),便于断言是否传了空的 -r。
	body := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + recFile + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, recFile
}

// readonly 创建不应再传 pure-pw 的 -r 空参(旧 bug:`-r ""`)。
func TestCreateReadonlyDoesNotPassEmptyR(t *testing.T) {
	script, recFile := fakePurePW(t)
	b := &pureFTPd{purePW: script, pureDB: script, uid: "1000", gid: "1000"}

	if err := b.create(context.Background(), "bob", "pw123456", "/home/ftp/bob", true, 0); err != nil {
		t.Fatalf("create returned error: %v", err)
	}
	raw, err := os.ReadFile(recFile)
	if err != nil {
		t.Fatalf("argv not recorded: %v", err)
	}
	args := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	for i, a := range args {
		if a == "-r" {
			t.Fatalf("readonly create must not pass pure-pw -r flag, argv=%v", args)
		}
		if a == "" {
			t.Fatalf("create passed an empty argv at %d: %v", i, args)
		}
	}
	// 基本参数仍在。
	joined := strings.Join(args, " ")
	for _, want := range []string{"useradd", "bob", "-u 1000", "-g 1000", "-d /home/ftp/bob", "-m"} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv missing %q; got %q", want, joined)
		}
	}
	// quota 0 时不应传 -N。
	if strings.Contains(joined, "-N") {
		t.Errorf("zero quota must not pass -N; got %q", joined)
	}
}

func TestCreatePassesQuotaFlag(t *testing.T) {
	script, recFile := fakePurePW(t)
	b := &pureFTPd{purePW: script, pureDB: script, uid: "1000", gid: "1000"}
	if err := b.create(context.Background(), "bob", "pw123456", "/home/ftp/bob", false, 500); err != nil {
		t.Fatalf("create returned error: %v", err)
	}
	raw, _ := os.ReadFile(recFile)
	args := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-N 500") {
		t.Errorf("create with quota must pass -N 500; got %q", joined)
	}
}

func TestSetQuotaPassesUsermodN(t *testing.T) {
	script, recFile := fakePurePW(t)
	b := &pureFTPd{purePW: script, pureDB: script, uid: "1000", gid: "1000"}
	if err := b.setQuota(context.Background(), "bob", 1024); err != nil {
		t.Fatalf("setQuota returned error: %v", err)
	}
	raw, _ := os.ReadFile(recFile)
	args := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	joined := strings.Join(args, " ")
	for _, want := range []string{"usermod", "bob", "-N 1024", "-m"} {
		if !strings.Contains(joined, want) {
			t.Errorf("setQuota argv missing %q; got %q", want, joined)
		}
	}
}
