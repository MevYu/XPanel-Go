package dns

import (
	"strings"
	"testing"
)

func TestEncryptRoundTrip(t *testing.T) {
	c, err := newCryptor("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"api-token-abc", "with spaces & symbols!@#", "凭证-密钥"} {
		enc, err := c.encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		if enc == plain || strings.Contains(enc, plain) {
			t.Errorf("ciphertext leaks plaintext for %q", plain)
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
	if enc, err := c.encrypt(""); err != nil || enc != "" {
		t.Errorf("encrypt(\"\") = %q, %v", enc, err)
	}
	if dec, err := c.decrypt(""); err != nil || dec != "" {
		t.Errorf("decrypt(\"\") = %q, %v", dec, err)
	}
}

func TestEncryptNonceVaries(t *testing.T) {
	c, _ := newCryptor("s")
	a, _ := c.encrypt("same")
	b, _ := c.encrypt("same")
	if a == b {
		t.Error("nonce reuse: identical ciphertext for same plaintext")
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
