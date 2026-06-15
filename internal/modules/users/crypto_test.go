package users

import (
	"strings"
	"testing"
)

func TestSecretBoxRoundTrip(t *testing.T) {
	box := newSecretBox("super-secret-host-key")
	plain := []byte("JBSWY3DPEHPK3PXP") // 典型 base32 TOTP 密钥
	enc, err := box.encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if strings.Contains(enc, string(plain)) {
		t.Fatalf("ciphertext leaks plaintext: %q", enc)
	}
	got, err := box.decrypt(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plain)
	}
}

func TestSecretBoxNonceRandomized(t *testing.T) {
	box := newSecretBox("k")
	a, _ := box.encrypt([]byte("same"))
	b, _ := box.encrypt([]byte("same"))
	if a == b {
		t.Fatal("two encryptions of same plaintext must differ (random nonce)")
	}
}

func TestSecretBoxWrongKeyFails(t *testing.T) {
	enc, _ := newSecretBox("key-one").encrypt([]byte("secret"))
	if _, err := newSecretBox("key-two").decrypt(enc); err != errDecrypt {
		t.Fatalf("decrypt with wrong key should fail with errDecrypt, got %v", err)
	}
}

func TestSecretBoxRejectsGarbage(t *testing.T) {
	box := newSecretBox("k")
	if _, err := box.decrypt("not-base64-!!!"); err != errDecrypt {
		t.Fatalf("garbage should fail with errDecrypt, got %v", err)
	}
	if _, err := box.decrypt("AAAA"); err != errDecrypt {
		t.Fatalf("too-short input should fail with errDecrypt, got %v", err)
	}
}

func TestAPIKeyHashStorage(t *testing.T) {
	plain, hash, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(plain, "xpk_") {
		t.Errorf("plain key should have xpk_ prefix, got %q", plain)
	}
	if plain == hash || strings.Contains(hash, plain) {
		t.Fatal("stored hash must not equal/contain plaintext")
	}
	if !apiKeyMatches(plain, hash) {
		t.Fatal("matching key should verify against its hash")
	}
	if apiKeyMatches(plain+"x", hash) {
		t.Fatal("wrong key must not verify")
	}
}

func TestAPIKeyHashDeterministic(t *testing.T) {
	if hashAPIKey("xpk_abc") != hashAPIKey("xpk_abc") {
		t.Fatal("hash must be deterministic for lookup")
	}
}

func TestGenerateAPIKeyUnique(t *testing.T) {
	a, _, _ := generateAPIKey()
	b, _, _ := generateAPIKey()
	if a == b {
		t.Fatal("generated keys must be unique")
	}
}
