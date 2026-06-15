package store

import (
	"testing"
	"time"
)

func TestRefreshTokenLifecycle(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	u, _ := s.CreateUser("admin", "h", "admin")

	id, err := s.CreateRefreshToken(u.ID, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	got, err := s.GetValidRefreshToken(id)
	if err != nil {
		t.Fatalf("GetValidRefreshToken: %v", err)
	}
	if got.UserID != u.ID {
		t.Errorf("want uid %d, got %d", u.ID, got.UserID)
	}

	if err := s.RevokeRefreshToken(id); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}
	if _, err := s.GetValidRefreshToken(id); err != ErrNotFound {
		t.Errorf("revoked token should be ErrNotFound, got %v", err)
	}
}

func TestExpiredRefreshTokenInvalid(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	u, _ := s.CreateUser("admin", "h", "admin")
	id, _ := s.CreateRefreshToken(u.ID, time.Now().Add(-time.Hour).Unix())
	if _, err := s.GetValidRefreshToken(id); err != ErrNotFound {
		t.Errorf("expired token should be ErrNotFound, got %v", err)
	}
}
