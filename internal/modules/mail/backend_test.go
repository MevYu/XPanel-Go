package mail

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeBin 写一个把每个 argv 各一行落盘的脚本,返回脚本路径与录制文件路径。
func fakeBin(t *testing.T) (script, recFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake not supported on windows")
	}
	dir := t.TempDir()
	recFile = filepath.Join(dir, "argv")
	script = filepath.Join(dir, "bin")
	body := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + recFile + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, recFile
}

func TestAvailableRequiresPostfix(t *testing.T) {
	b := &postfixDovecot{}
	if b.available() == nil {
		t.Error("missing postfix should be unavailable")
	}
	b.postfix = "/usr/sbin/postfix"
	if b.available() != nil {
		t.Error("present postfix should be available")
	}
}

func TestSyncDomainsWritesMapAndPostmaps(t *testing.T) {
	script, recFile := fakeBin(t)
	dir := t.TempDir()
	domFile := filepath.Join(dir, "virtual_domains")
	b := &postfixDovecot{postfix: script, postmap: script}
	s := Settings{VirtualDomainFile: domFile}
	if err := b.syncDomains(context.Background(), s, []string{"b.com", "a.com"}); err != nil {
		t.Fatalf("syncDomains: %v", err)
	}
	content, err := os.ReadFile(domFile)
	if err != nil {
		t.Fatal(err)
	}
	// 排序后 a.com 在前,格式 "<domain>\tOK"。
	got := string(content)
	if !strings.Contains(got, "a.com\tOK") || !strings.Contains(got, "b.com\tOK") {
		t.Fatalf("domain map content wrong: %q", got)
	}
	if strings.Index(got, "a.com") > strings.Index(got, "b.com") {
		t.Errorf("domains should be sorted, got %q", got)
	}
	// postmap 收到 hash:<file> 单参数,无 shell。
	raw, _ := os.ReadFile(recFile)
	args := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(args) != 1 || args[0] != "hash:"+domFile {
		t.Fatalf("postmap argv wrong: %v", args)
	}
}

func TestSyncMailboxesWritesUserHashNotPlaintext(t *testing.T) {
	script, _ := fakeBin(t)
	dir := t.TempDir()
	mbxFile := filepath.Join(dir, "vmailbox")
	dovecotDir := t.TempDir()
	b := &postfixDovecot{postfix: script, postmap: script}
	s := Settings{VirtualMailboxFile: mbxFile, DovecotConfigDir: dovecotDir}
	boxes := []mailboxUser{{
		Address:      "bob@example.com",
		Maildir:      "example.com/bob/",
		QuotaMB:      200,
		PasswordHash: "{SHA512-CRYPT}$6$abc$hashed",
	}}
	if err := b.syncMailboxes(context.Background(), s, boxes); err != nil {
		t.Fatalf("syncMailboxes: %v", err)
	}
	// postfix vmailbox map: 地址 -> maildir。
	mbx, _ := os.ReadFile(mbxFile)
	if !strings.Contains(string(mbx), "bob@example.com\texample.com/bob/") {
		t.Fatalf("vmailbox content wrong: %q", mbx)
	}
	// dovecot users 文件含哈希与配额,不含明文(此处无明文可比,断言哈希在)。
	users, err := os.ReadFile(filepath.Join(dovecotDir, "users"))
	if err != nil {
		t.Fatal(err)
	}
	u := string(users)
	if !strings.Contains(u, "{SHA512-CRYPT}") {
		t.Fatalf("dovecot users should contain hash, got %q", u)
	}
	if !strings.Contains(u, "storage=200M") {
		t.Fatalf("dovecot users should contain quota, got %q", u)
	}
}

func TestSyncAliasesMergesMultipleDestinations(t *testing.T) {
	script, _ := fakeBin(t)
	dir := t.TempDir()
	aliasFile := filepath.Join(dir, "virtual")
	b := &postfixDovecot{postfix: script, postmap: script}
	s := Settings{VirtualAliasFile: aliasFile}
	aliases := []aliasMeta{
		{Source: "info@example.com", Destination: "bob@example.com"},
		{Source: "info@example.com", Destination: "alice@example.com"},
	}
	if err := b.syncAliases(context.Background(), s, aliases); err != nil {
		t.Fatalf("syncAliases: %v", err)
	}
	content, _ := os.ReadFile(aliasFile)
	got := string(content)
	// 同 source 多目标合并到一行,逗号分隔。
	if !strings.Contains(got, "info@example.com\talice@example.com,bob@example.com") {
		t.Fatalf("alias merge wrong: %q", got)
	}
	if strings.Count(got, "info@example.com") != 1 {
		t.Errorf("source should appear once, got %q", got)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := writeFileAtomic(p, "hello", 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "hello" {
		t.Errorf("got %q", got)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Error("tmp file should be renamed away")
	}
}
