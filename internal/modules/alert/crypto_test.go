package alert

import (
	"strings"
	"testing"
)

func TestEncryptRoundTrip(t *testing.T) {
	c, err := newCryptor("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"smtp-pass", "bot:123456:AAH-token", "unicode-密码 & symbols!@#"} {
		enc, err := c.encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		if enc == plain {
			t.Errorf("ciphertext equals plaintext for %q", plain)
		}
		if strings.Contains(enc, plain) {
			t.Errorf("ciphertext contains plaintext for %q", plain)
		}
		got, err := c.decrypt(enc)
		if err != nil {
			t.Fatal(err)
		}
		if got != plain {
			t.Errorf("round-trip = %q, want %q", got, plain)
		}
	}
}

func TestEncryptEmptyIsEmpty(t *testing.T) {
	c, _ := newCryptor("s")
	enc, err := c.encrypt("")
	if err != nil || enc != "" {
		t.Errorf("encrypt(\"\") = %q, %v", enc, err)
	}
	dec, err := c.decrypt("")
	if err != nil || dec != "" {
		t.Errorf("decrypt(\"\") = %q, %v", dec, err)
	}
}

func TestEncryptNonceVaries(t *testing.T) {
	c, _ := newCryptor("s")
	a, _ := c.encrypt("same")
	b, _ := c.encrypt("same")
	if a == b {
		t.Error("two encryptions of same plaintext produced identical ciphertext (nonce reuse)")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	c1, _ := newCryptor("key1")
	c2, _ := newCryptor("key2")
	enc, _ := c1.encrypt("secret")
	if _, err := c2.decrypt(enc); err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestDecryptGarbageFails(t *testing.T) {
	c, _ := newCryptor("s")
	for _, bad := range []string{"not-base64!!!", "AAAA"} {
		if _, err := c.decrypt(bad); err == nil {
			t.Errorf("decrypt(%q) should fail", bad)
		}
	}
}
