package sites

import (
	"strings"
	"testing"
)

func TestApr1Hash(t *testing.T) {
	// 已知向量:openssl passwd -apr1 -salt SALTSALT password
	got := apr1("SALTSALT", "password")
	const want = "$apr1$SALTSALT$N6V/2.tFDumAmC5CPh/el1" // openssl passwd -apr1 -salt SALTSALT password
	if got != want {
		t.Errorf("apr1 = %q, want %q", got, want)
	}
}

func TestHtpasswdLineFormat(t *testing.T) {
	h := newAPR1Hasher(func(int) (string, error) { return "abcdefgh", nil })
	hash, err := h.Hash("secret")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$apr1$abcdefgh$") {
		t.Errorf("hash %q missing apr1 prefix/salt", hash)
	}
	line := htpasswdLine("admin", hash)
	if line != "admin:"+hash+"\n" {
		t.Errorf("htpasswdLine = %q", line)
	}
	// 用户名含冒号会破坏 .htpasswd 格式,必须在上层拒绝;此处确保哈希不含冒号/换行。
	if strings.ContainsAny(hash, ":\n\r") {
		t.Errorf("apr1 hash must not contain : or newline, got %q", hash)
	}
}

func TestHtpasswdFileContent(t *testing.T) {
	entries := []DirProtect{
		{Path: "/admin", Username: "admin", PassHash: "$apr1$x$y"},
		{Path: "/admin", Username: "ops", PassHash: "$apr1$a$b"},
	}
	content := htpasswdFile(entries)
	if content != "admin:$apr1$x$y\nops:$apr1$a$b\n" {
		t.Errorf("htpasswdFile = %q", content)
	}
}
