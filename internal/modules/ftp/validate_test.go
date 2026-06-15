package ftp

import "testing"

func TestValidUserRejectsInjection(t *testing.T) {
	bad := []string{
		"", "../etc", "a/b", "a;rm -rf", "a b", "a$b", "-rf", ".hidden",
		"a\nb", "a`b", "user|cat", "u'", "u\"", "тест",
		"toolongtoolongtoolongtoolongtoolong", // >32
	}
	for _, s := range bad {
		if validUser(s) {
			t.Errorf("validUser(%q) = true, want false", s)
		}
	}
	good := []string{"alice", "bob_1", "web-user", "a", "User.Name", "A1b2c3"}
	for _, s := range good {
		if !validUser(s) {
			t.Errorf("validUser(%q) = false, want true", s)
		}
	}
}

func TestValidPassword(t *testing.T) {
	if validPassword("") {
		t.Error("empty password must be rejected")
	}
	if validPassword("ab\ncd") {
		t.Error("password with newline must be rejected (injection)")
	}
	if validPassword("ab\x00cd") {
		t.Error("password with NUL must be rejected")
	}
	if !validPassword("S3cret!@# spaces ok") {
		t.Error("normal password must be accepted")
	}
	long := make([]byte, 257)
	for i := range long {
		long[i] = 'a'
	}
	if validPassword(string(long)) {
		t.Error("over-length password must be rejected")
	}
}

func TestResolveHomeRejectsEscape(t *testing.T) {
	base := "/home/ftp"
	bad := []string{
		"/home/ftp/../../etc",
		"/etc/passwd",
		"relative/path",
		"/home/ftpother", // 前缀但非子目录
		"",
	}
	for _, h := range bad {
		if _, err := resolveHome(base, h); err == nil {
			t.Errorf("resolveHome(%q) should fail", h)
		}
	}
	got, err := resolveHome(base, "/home/ftp/alice")
	if err != nil || got != "/home/ftp/alice" {
		t.Errorf("resolveHome valid = %q, %v", got, err)
	}
	// base 自身允许
	if _, err := resolveHome(base, "/home/ftp"); err != nil {
		t.Errorf("resolveHome(base) should pass: %v", err)
	}
	// 含 .. 但归一化后仍在 base 内
	got, err = resolveHome(base, "/home/ftp/x/../bob")
	if err != nil || got != "/home/ftp/bob" {
		t.Errorf("resolveHome normalize = %q, %v", got, err)
	}
}
