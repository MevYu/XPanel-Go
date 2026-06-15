package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestIssueAndParseAccessToken(t *testing.T) {
	jm := NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	tok, err := jm.Issue(42, "admin")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := jm.Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if claims.UserID != 42 || claims.Role != "admin" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestParseRejectsBadSignature(t *testing.T) {
	tok, _ := NewJWTManager([]byte("secret-aaaaaaaaaaaaaaaaaaaaaaaaaaa")).Issue(1, "admin")
	if _, err := NewJWTManager([]byte("secret-bbbbbbbbbbbbbbbbbbbbbbbbbbb")).Parse(tok); err == nil {
		t.Error("token signed with different secret must be rejected")
	}
}

func TestParseRejectsHS512(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-xxxxxx")
	claims := Claims{UserID: 1, Role: "admin"}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign HS512 token: %v", err)
	}
	if _, err := NewJWTManager(secret).Parse(tok); err == nil {
		t.Error("HS512 token must be rejected; only HS256 allowed")
	}
}

func TestParseRejectsNoneAlg(t *testing.T) {
	claims := Claims{UserID: 1, Role: "admin"}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}
	if _, err := NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx")).Parse(tok); err == nil {
		t.Error("alg=none token must be rejected")
	}
}
