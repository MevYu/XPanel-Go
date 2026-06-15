package backup

import "testing"

func TestCryptoRoundTrip(t *testing.T) {
	c, err := newCryptor("panel-secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"", "aws-secret-key", "with spaces & symbols/+="} {
		enc, err := c.encrypt(plain)
		if err != nil {
			t.Fatalf("encrypt %q: %v", plain, err)
		}
		if plain != "" && enc == plain {
			t.Errorf("ciphertext equals plaintext for %q", plain)
		}
		got, err := c.decrypt(enc)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != plain {
			t.Errorf("round-trip = %q, want %q", got, plain)
		}
	}
}

func TestCryptoWrongKeyFails(t *testing.T) {
	a, _ := newCryptor("key-a")
	b, _ := newCryptor("key-b")
	enc, _ := a.encrypt("secret")
	if _, err := b.decrypt(enc); err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestCryptoNonceUnique(t *testing.T) {
	c, _ := newCryptor("k")
	e1, _ := c.encrypt("same")
	e2, _ := c.encrypt("same")
	if e1 == e2 {
		t.Error("same plaintext produced identical ciphertext (nonce reuse)")
	}
}
