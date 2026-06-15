package database

import (
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newTestSettings(t *testing.T) *settingsStore {
	t.Helper()
	cryp, err := newCryptor("secret")
	if err != nil {
		t.Fatal(err)
	}
	ss, err := newSettingsStore(newTestStore(t), cryp)
	if err != nil {
		t.Fatal(err)
	}
	return ss
}

func TestEffectiveDefaultsWhenUnset(t *testing.T) {
	ss := newTestSettings(t)
	eff, err := ss.effective()
	if err != nil {
		t.Fatal(err)
	}
	def := defaultSettings()
	if eff.MySQLPort != def.MySQLPort || eff.MySQLDataDir != def.MySQLDataDir {
		t.Errorf("mysql defaults not applied: %+v", eff)
	}
	if eff.PGDataDir != def.PGDataDir || eff.PGPort != def.PGPort {
		t.Errorf("pg defaults not applied: %+v", eff)
	}
	if eff.RedisPort != def.RedisPort || eff.BackupDir != def.BackupDir {
		t.Errorf("redis/backup defaults not applied: %+v", eff)
	}
}

func TestSaveOverridesAndDefaultsFill(t *testing.T) {
	ss := newTestSettings(t)
	in := Settings{MySQLPort: 3307, BackupDir: "/custom/backups"}
	if err := ss.save(in); err != nil {
		t.Fatal(err)
	}
	eff, err := ss.effective()
	if err != nil {
		t.Fatal(err)
	}
	if eff.MySQLPort != 3307 {
		t.Errorf("override MySQLPort = %d, want 3307", eff.MySQLPort)
	}
	if eff.BackupDir != "/custom/backups" {
		t.Errorf("override BackupDir = %q", eff.BackupDir)
	}
	// 未覆盖字段回落默认
	if eff.PGDataDir != defaultSettings().PGDataDir {
		t.Errorf("unset PGDataDir should fall back to default, got %q", eff.PGDataDir)
	}
}

func TestPasswordEncryptedAtRestAndMasked(t *testing.T) {
	st := newTestStore(t)
	cryp, _ := newCryptor("secret")
	ss, _ := newSettingsStore(st, cryp)
	if err := ss.save(Settings{MySQLPassword: "topsecret"}); err != nil {
		t.Fatal(err)
	}
	// 落库密文不应等于/包含明文
	var stored string
	if err := st.DB.QueryRow(`SELECT mysql_password FROM database_settings WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "" || stored == "topsecret" {
		t.Errorf("stored password not encrypted: %q", stored)
	}
	// effective 解密回明文(供内部建连)
	eff, _ := ss.effective()
	if eff.MySQLPassword != "topsecret" {
		t.Errorf("effective password = %q, want topsecret", eff.MySQLPassword)
	}
	// masked 屏蔽密码,但标记已设
	m, set, _ := ss.masked()
	if m.MySQLPassword != "" {
		t.Errorf("masked must hide password, got %q", m.MySQLPassword)
	}
	found := false
	for _, k := range set {
		if k == "mysql" {
			found = true
		}
	}
	if !found {
		t.Errorf("passwords_set should include mysql, got %v", set)
	}
}

func TestSaveEmptyPasswordKeepsPrevious(t *testing.T) {
	ss := newTestSettings(t)
	_ = ss.save(Settings{MySQLPassword: "orig"})
	// 后续保存不带密码,应保留原密码
	_ = ss.save(Settings{MySQLPort: 3308})
	eff, _ := ss.effective()
	if eff.MySQLPassword != "orig" {
		t.Errorf("empty password save should keep previous, got %q", eff.MySQLPassword)
	}
}
