package users

import (
	"errors"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) (*userStore, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	us, err := newUserStore(st)
	if err != nil {
		t.Fatalf("new user store: %v", err)
	}
	return us, st
}

func TestNewUserStoreIdempotent(t *testing.T) {
	_, st := newTestStore(t)
	if _, err := newUserStore(st); err != nil {
		t.Fatalf("second newUserStore should be idempotent: %v", err)
	}
}

func TestUserCRUD(t *testing.T) {
	us, _ := newTestStore(t)
	id, err := us.createUser("alice", "hash1", "operator")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	taken, _ := us.usernameTaken("alice")
	if !taken {
		t.Fatal("alice should be taken")
	}
	list, err := us.listUsers()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].Username != "alice" || list[0].Role != "operator" || list[0].TOTPEnabled {
		t.Fatalf("unexpected list: %+v", list)
	}
	if err := us.setRole(id, "admin"); err != nil {
		t.Fatalf("setRole: %v", err)
	}
	if role, _ := us.getRole(id); role != "admin" {
		t.Fatalf("role not updated, got %q", role)
	}
	if err := us.setPassword(id, "hash2"); err != nil {
		t.Fatalf("setPassword: %v", err)
	}
	if err := us.deleteUser(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if exists, _ := us.userExists(id); exists {
		t.Fatal("user should be gone")
	}
}

func TestCountAdmins(t *testing.T) {
	us, _ := newTestStore(t)
	us.createUser("a1", "h", "admin")
	us.createUser("a2", "h", "admin")
	us.createUser("op", "h", "operator")
	n, err := us.countAdmins()
	if err != nil {
		t.Fatalf("countAdmins: %v", err)
	}
	if n != 2 {
		t.Fatalf("want 2 admins, got %d", n)
	}
}

func TestTOTPLifecycle(t *testing.T) {
	us, _ := newTestStore(t)
	uid, _ := us.createUser("bob", "h", "admin")

	if _, err := us.getTOTP(uid); !errors.Is(err, errNotFound) {
		t.Fatalf("expected errNotFound before setup, got %v", err)
	}
	if err := us.upsertTOTP(uid, "ENC1", false); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	row, err := us.getTOTP(uid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.SecretEnc != "ENC1" || row.Enabled {
		t.Fatalf("unexpected row: %+v", row)
	}
	// 重新 setup 覆盖密钥并保持 disabled。
	if err := us.upsertTOTP(uid, "ENC2", false); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	row, _ = us.getTOTP(uid)
	if row.SecretEnc != "ENC2" {
		t.Fatalf("secret not overwritten, got %q", row.SecretEnc)
	}
	if err := us.setTOTPEnabled(uid, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	row, _ = us.getTOTP(uid)
	if !row.Enabled {
		t.Fatal("should be enabled")
	}
	// listUsers 应反映 totp_enabled。
	list, _ := us.listUsers()
	if !list[0].TOTPEnabled {
		t.Fatal("listUsers should show totp enabled")
	}
	if err := us.deleteTOTP(uid); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := us.getTOTP(uid); !errors.Is(err, errNotFound) {
		t.Fatalf("expected errNotFound after delete, got %v", err)
	}
}

func TestSetTOTPEnabledMissing(t *testing.T) {
	us, _ := newTestStore(t)
	if err := us.setTOTPEnabled(999, true); !errors.Is(err, errNotFound) {
		t.Fatalf("enabling missing totp should errNotFound, got %v", err)
	}
}

func TestAPIKeyStore(t *testing.T) {
	us, _ := newTestStore(t)
	uid, _ := us.createUser("carol", "h", "operator")
	other, _ := us.createUser("dave", "h", "operator")

	id, err := us.createAPIKey(uid, "ci", "hash-aaa")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	keys, _ := us.listAPIKeys(uid)
	if len(keys) != 1 || keys[0].Name != "ci" || keys[0].LastUsedAt != nil {
		t.Fatalf("unexpected keys: %+v", keys)
	}
	// 越权吊销:other 删不掉 uid 的 key。
	hit, err := us.revokeAPIKey(other, id)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if hit {
		t.Fatal("must not revoke another user's key")
	}
	// 本人吊销成功。
	hit, _ = us.revokeAPIKey(uid, id)
	if !hit {
		t.Fatal("owner should revoke own key")
	}
	keys, _ = us.listAPIKeys(uid)
	if len(keys) != 0 {
		t.Fatalf("key should be gone, got %+v", keys)
	}
}

func TestDeleteUserCascadesKeysAndTOTP(t *testing.T) {
	us, _ := newTestStore(t)
	uid, _ := us.createUser("erin", "h", "operator")
	us.createAPIKey(uid, "k", "h1")
	us.upsertTOTP(uid, "ENC", true)
	if err := us.deleteUser(uid); err != nil {
		t.Fatalf("delete: %v", err)
	}
	keys, _ := us.listAPIKeys(uid)
	if len(keys) != 0 {
		t.Fatal("api keys should be cascaded")
	}
	if _, err := us.getTOTP(uid); !errors.Is(err, errNotFound) {
		t.Fatal("totp should be cascaded")
	}
}

func TestSettings(t *testing.T) {
	us, _ := newTestStore(t)
	v, err := us.getSetting(settingTOTPIssuer, defaultTOTPIssuer)
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if v != defaultTOTPIssuer {
		t.Fatalf("want default %q, got %q", defaultTOTPIssuer, v)
	}
	if err := us.setSetting(settingTOTPIssuer, "MyPanel"); err != nil {
		t.Fatalf("set: %v", err)
	}
	v, _ = us.getSetting(settingTOTPIssuer, defaultTOTPIssuer)
	if v != "MyPanel" {
		t.Fatalf("want MyPanel, got %q", v)
	}
}
