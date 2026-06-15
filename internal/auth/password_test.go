package auth

import "testing"

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
