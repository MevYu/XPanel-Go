package cron

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecRunnerCommand(t *testing.T) {
	r := &execRunner{logCutRoot: t.TempDir(), scriptDir: t.TempDir()}
	res := r.run(context.Background(), Job{
		Type: taskCommand, Payload: payload{Command: "echo hello && exit 0"},
	})
	if res.ExitCode != 0 {
		t.Errorf("want exit 0, got %d (err=%s)", res.ExitCode, res.Err)
	}
	if !strings.Contains(res.Output, "hello") {
		t.Errorf("output missing: %q", res.Output)
	}
}

func TestExecRunnerCapturesNonZeroExit(t *testing.T) {
	r := &execRunner{logCutRoot: t.TempDir(), scriptDir: t.TempDir()}
	res := r.run(context.Background(), Job{
		Type: taskCommand, Payload: payload{Command: "echo oops >&2; exit 7"},
	})
	if res.ExitCode != 7 {
		t.Errorf("want exit 7, got %d", res.ExitCode)
	}
	if !strings.Contains(res.Output, "oops") {
		t.Errorf("stderr not captured: %q", res.Output)
	}
}

func TestExecRunnerShellScript(t *testing.T) {
	dir := t.TempDir()
	r := &execRunner{logCutRoot: t.TempDir(), scriptDir: dir}
	res := r.run(context.Background(), Job{
		ID: 5, Type: taskShell, Payload: payload{Script: "#!/bin/sh\necho fromscript\n"},
	})
	if res.ExitCode != 0 || !strings.Contains(res.Output, "fromscript") {
		t.Errorf("shell script run failed: %+v", res)
	}
}

func TestExecRunnerLogCutTruncates(t *testing.T) {
	root := t.TempDir()
	logp := filepath.Join(root, "app.log")
	if err := os.WriteFile(logp, []byte("lots of log data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &execRunner{logCutRoot: root, scriptDir: t.TempDir()}
	res := r.run(context.Background(), Job{Type: taskLogCut, Payload: payload{Path: "app.log"}})
	if res.ExitCode != 0 {
		t.Fatalf("log_cut failed: %+v", res)
	}
	data, _ := os.ReadFile(logp)
	if len(data) != 0 {
		t.Errorf("log not truncated, size=%d", len(data))
	}
}

func TestExecRunnerBackupNotWired(t *testing.T) {
	r := &execRunner{logCutRoot: t.TempDir(), scriptDir: t.TempDir()}
	res := r.run(context.Background(), Job{Type: taskBackupSite, Payload: payload{Target: "site"}})
	if res.Err == "" {
		t.Errorf("backup_site should report not-wired error, got %+v", res)
	}
}

func TestCappedBufferTruncates(t *testing.T) {
	var b cappedBuffer
	b.limit = 10
	_, _ = b.Write([]byte("0123456789ABCDEF"))
	out := b.String()
	if !strings.Contains(out, "truncated") {
		t.Errorf("expected truncation marker: %q", out)
	}
	if !strings.HasPrefix(out, "0123456789") {
		t.Errorf("expected first 10 bytes kept: %q", out)
	}
}
