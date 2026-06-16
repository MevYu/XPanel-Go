package mysqlrepl

import "testing"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c, err := newCryptor("a-secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"p@ss w0rd", "短密码", "", "with'quote\\and"} {
		enc, err := c.encrypt(plain)
		if err != nil {
			t.Fatalf("encrypt(%q): %v", plain, err)
		}
		if plain != "" && enc == plain {
			t.Errorf("ciphertext equals plaintext for %q", plain)
		}
		got, err := c.decrypt(enc)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != plain {
			t.Errorf("round trip = %q, want %q", got, plain)
		}
	}
}

func TestEncryptNonDeterministic(t *testing.T) {
	c, _ := newCryptor("s")
	a, _ := c.encrypt("same")
	b, _ := c.encrypt("same")
	if a == b {
		t.Error("two encryptions of same plaintext must differ (random nonce)")
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
	if _, err := c.decrypt("not base64!!!"); err == nil {
		t.Error("decrypt garbage should fail")
	}
	if _, err := c.decrypt("YWJj"); err == nil {
		t.Error("decrypt too-short ciphertext should fail")
	}
}
