package store

import "testing"

func TestCreateAndGetUser(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()

	u, err := s.CreateUser("admin", "hash123", "admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == 0 {
		t.Error("expected non-zero id")
	}

	got, err := s.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.PassHash != "hash123" || got.Role != "admin" {
		t.Errorf("unexpected user: %+v", got)
	}

	if _, err := s.CreateUser("admin", "x", "admin"); err == nil {
		t.Error("duplicate username should error")
	}

	if _, err := s.GetUserByUsername("nobody"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCountUsers(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	if n, _ := s.CountUsers(); n != 0 {
		t.Errorf("want 0, got %d", n)
	}
	s.CreateUser("a", "h", "admin")
	if n, _ := s.CountUsers(); n != 1 {
		t.Errorf("want 1, got %d", n)
	}
}
