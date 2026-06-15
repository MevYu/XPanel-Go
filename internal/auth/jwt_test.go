package auth

import "testing"

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
