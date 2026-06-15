package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSSHDirectiveWhitelist(t *testing.T) {
	// 非白名单键必须被拒。
	bad := []string{"AllowUsers", "Subsystem", "Match", "Banner", "Include", "rm -rf"}
	for _, k := range bad {
		if err := ValidateSSHDirective(k, "x"); err == nil {
			t.Errorf("non-whitelist key %q must be rejected", k)
		}
	}
	// 白名单键 + 合法值通过。
	ok := map[string]string{
		"Port":                   "2222",
		"PermitRootLogin":        "prohibit-password",
		"PasswordAuthentication": "no",
		"MaxAuthTries":           "3",
		"ClientAliveInterval":    "0",
	}
	for k, v := range ok {
		if err := ValidateSSHDirective(k, v); err != nil {
			t.Errorf("whitelist %s=%s should pass, got %v", k, v, err)
		}
	}
}

func TestValidateSSHDirectiveBadValues(t *testing.T) {
	cases := map[string]string{
		"Port":                   "70000",  // 越界
		"PasswordAuthentication": "maybe",  // 非 yes/no
		"PermitRootLogin":        "always", // 非法枚举
		"MaxAuthTries":           "0",      // 须 >0
		"ClientAliveInterval":    "-5",     // 须 >=0
	}
	for k, v := range cases {
		if err := ValidateSSHDirective(k, v); err == nil {
			t.Errorf("%s=%s should be rejected", k, v)
		}
	}
}

func TestSSHKeyDangerous(t *testing.T) {
	for _, k := range []string{"Port", "PasswordAuthentication", "PermitRootLogin", "PubkeyAuthentication"} {
		if !SSHKeyDangerous(k) {
			t.Errorf("%s must be flagged dangerous", k)
		}
	}
	if SSHKeyDangerous("MaxAuthTries") {
		t.Error("MaxAuthTries must not be dangerous")
	}
}

func TestValidatePublicKey(t *testing.T) {
	good := "ssh-ed25519 AAAAC3aaaQ== user@host"
	norm, err := ValidatePublicKey("  " + good + "  ")
	if err != nil || norm != good {
		t.Fatalf("valid key should pass and trim, got %q err=%v", norm, err)
	}
	bad := []string{
		"",                                   // 空
		"notakey blah",                       // 类型非法
		"ssh-rsa !!!notbase64!!!",            // 主体非 base64
		"ssh-ed25519",                        // 缺主体
		"ssh-ed25519 AAAAC3aa one\nrm -rf /", // 多行注入
		"ssh-ed25519 AAAAC3aa com$(reboot)",  // 注释非法字符
	}
	for _, k := range bad {
		if _, err := ValidatePublicKey(k); err == nil {
			t.Errorf("invalid key %q must be rejected", k)
		}
	}
}

func TestRewriteDirectiveReplacesAndComments(t *testing.T) {
	in := "# comment\nPort 22\nPasswordAuthentication yes\nPort 2200\n"
	out := rewriteDirective(in, "Port", "2222")
	if !strings.Contains(out, "Port 2222") {
		t.Errorf("expected Port 2222 in:\n%s", out)
	}
	// 第二个 Port 行须被注释掉。
	if strings.Contains(out, "\nPort 2200") {
		t.Errorf("duplicate Port line must be commented out:\n%s", out)
	}
	if strings.Contains(out, "\nPort 22\n") {
		t.Errorf("original Port line must be replaced:\n%s", out)
	}
}

func TestRewriteDirectiveAppendsWhenMissing(t *testing.T) {
	out := rewriteDirective("Port 22\n", "MaxAuthTries", "3")
	if !strings.Contains(out, "MaxAuthTries 3") {
		t.Errorf("missing directive must be appended:\n%s", out)
	}
}

func TestAuthorizedKeysRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "authorized_keys")
	k1 := "ssh-ed25519 AAAAC3aaaQ== one@host"
	k2 := "ssh-rsa AAAAB3bbbg== two@host"

	if err := AddAuthorizedKey(path, k1); err != nil {
		t.Fatal(err)
	}
	if err := AddAuthorizedKey(path, k1); err != nil { // 幂等
		t.Fatal(err)
	}
	if err := AddAuthorizedKey(path, k2); err != nil {
		t.Fatal(err)
	}
	keys, err := ReadAuthorizedKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (idempotent add), got %d: %v", len(keys), keys)
	}
	// 文件权限须 0600。
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys must be 0600, got %v", info.Mode().Perm())
	}

	if err := RemoveAuthorizedKey(path, k1); err != nil {
		t.Fatal(err)
	}
	keys, _ = ReadAuthorizedKeys(path)
	if len(keys) != 1 || keys[0] != k2 {
		t.Fatalf("after remove expected [k2], got %v", keys)
	}
}

func TestAddAuthorizedKeyRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := AddAuthorizedKey(path, "garbage notakey"); err == nil {
		t.Error("invalid key must not be written")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file must not be created when key is invalid")
	}
}

func TestParseBannedIPs(t *testing.T) {
	out := `Status for the jail: sshd
|- Filter
|  |- Currently failed: 1
` + "`- Actions\n   `- Banned IP list:\t1.2.3.4 5.6.7.8\n"
	ips := parseBannedIPs(out)
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Fatalf("expected [1.2.3.4 5.6.7.8], got %v", ips)
	}
	if got := parseBannedIPs("Banned IP list:\t\n"); got != nil {
		t.Errorf("empty list must be nil, got %v", got)
	}
}

func TestParseLastOutput(t *testing.T) {
	out := "root  pts/0  1.2.3.4  Mon Jun 15 10:00 - 10:30\nwtmp begins ...\nbtmp begins ...\n"
	entries := parseLastOutput(out, true)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (wtmp/btmp skipped), got %d: %v", len(entries), entries)
	}
	e := entries[0]
	if e.User != "root" || e.IP != "1.2.3.4" || !e.Failed {
		t.Errorf("unexpected entry: %+v", e)
	}
}
