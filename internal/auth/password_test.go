package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("s3cret-pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "s3cret-pw" {
		t.Fatal("hash must not equal plaintext")
	}
	if !VerifyPassword(hash, "s3cret-pw") {
		t.Error("correct password should verify")
	}
	if VerifyPassword(hash, "wrong-pw") {
		t.Error("wrong password must not verify")
	}
}

func TestVerifyPasswordRejectsTamperedVersion(t *testing.T) {
	hash, err := HashPassword("s3cret-pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	tampered := strings.Replace(hash, "v=19", "v=18", 1)
	if tampered == hash {
		t.Fatal("expected hash to contain v=19")
	}
	if VerifyPassword(tampered, "s3cret-pw") {
		t.Error("tampered PHC version must not verify")
	}
}
