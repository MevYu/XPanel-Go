package auth

import (
	"testing"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	jm := NewJWTManager([]byte("test-secret-32-bytes-long-xxxxxx"))
	lo := NewLockout(3, time.Minute, time.Now)
	return NewService(s, jm, lo), s
}

func TestRegisterThenLogin(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.Register("admin", "pw-123456", "admin"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	tokens, err := svc.Login("admin", "pw-123456", "1.2.3.4")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tokens.Access == "" || tokens.Refresh == "" {
		t.Error("expected non-empty tokens")
	}
}

func TestLoginWrongPasswordCountsTowardLockout(t *testing.T) {
	svc, _ := newTestService(t)
	svc.Register("admin", "pw-123456", "admin")
	for i := 0; i < 3; i++ {
		if _, err := svc.Login("admin", "wrong", "1.2.3.4"); err != ErrInvalidCredentials {
			t.Fatalf("attempt %d: want ErrInvalidCredentials, got %v", i, err)
		}
	}
	// 锁定后即便密码正确也拒绝
	if _, err := svc.Login("admin", "pw-123456", "1.2.3.4"); err != ErrLockedOut {
		t.Errorf("want ErrLockedOut, got %v", err)
	}
}

func TestRefreshRotatesAndRevokes(t *testing.T) {
	svc, _ := newTestService(t)
	svc.Register("admin", "pw-123456", "admin")
	tok, _ := svc.Login("admin", "pw-123456", "1.2.3.4")

	next, err := svc.Refresh(tok.Refresh, "1.2.3.4")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if next.Refresh == tok.Refresh {
		t.Error("refresh should rotate to a new token")
	}
	// 旧 refresh 已被撤销
	if _, err := svc.Refresh(tok.Refresh, "1.2.3.4"); err != ErrInvalidCredentials {
		t.Errorf("old refresh should be revoked, got %v", err)
	}
}

func TestLogoutRevokesRefresh(t *testing.T) {
	svc, _ := newTestService(t)
	svc.Register("admin", "pw-123456", "admin")
	tok, _ := svc.Login("admin", "pw-123456", "1.2.3.4")
	if err := svc.Logout(tok.Refresh, "1.2.3.4"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc.Refresh(tok.Refresh, "1.2.3.4"); err != ErrInvalidCredentials {
		t.Errorf("after logout refresh must fail, got %v", err)
	}
}

func TestFailedLoginWritesAudit(t *testing.T) {
	svc, st := newTestService(t)
	svc.Register("admin", "pw-123456", "admin")
	if _, err := svc.Login("admin", "wrong", "9.9.9.9"); err != ErrInvalidCredentials {
		t.Fatalf("want ErrInvalidCredentials, got %v", err)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, "login.failure").Scan(&n)
	if n != 1 {
		t.Errorf("want 1 login.failure audit row, got %d", n)
	}
}
