package mysqlrepl

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
	if eff.MasterPort != def.MasterPort || eff.MasterUser != def.MasterUser {
		t.Errorf("master defaults not applied: %+v", eff)
	}
	if eff.SlavePort != def.SlavePort || eff.SlaveHost != def.SlaveHost {
		t.Errorf("slave defaults not applied: %+v", eff)
	}
}

func TestSaveOverridesAndDefaultsFill(t *testing.T) {
	ss := newTestSettings(t)
	if err := ss.save(Settings{MasterPort: 13306, SlaveHost: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	eff, err := ss.effective()
	if err != nil {
		t.Fatal(err)
	}
	if eff.MasterPort != 13306 || eff.SlaveHost != "10.0.0.2" {
		t.Errorf("overrides not applied: %+v", eff)
	}
	// 未覆盖字段回落默认
	if eff.SlavePort != defaultSettings().SlavePort {
		t.Errorf("unset SlavePort should fall back to default, got %d", eff.SlavePort)
	}
}

func TestPasswordEncryptedAtRestAndMasked(t *testing.T) {
	st := newTestStore(t)
	cryp, _ := newCryptor("secret")
	ss, _ := newSettingsStore(st, cryp)
	if err := ss.save(Settings{MasterPassword: "topsecret", SlavePassword: "slavesecret"}); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := st.DB.QueryRow(`SELECT master_password FROM mysqlrepl_settings WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "" || stored == "topsecret" {
		t.Errorf("stored password not encrypted: %q", stored)
	}
	eff, _ := ss.effective()
	if eff.MasterPassword != "topsecret" || eff.SlavePassword != "slavesecret" {
		t.Errorf("effective passwords wrong: %+v", eff)
	}
	m, set, _ := ss.masked()
	if m.MasterPassword != "" || m.SlavePassword != "" {
		t.Errorf("masked must hide passwords: %+v", m)
	}
	if len(set) != 2 {
		t.Errorf("passwords_set should include master+slave, got %v", set)
	}
}

func TestSaveEmptyPasswordKeepsPrevious(t *testing.T) {
	ss := newTestSettings(t)
	_ = ss.save(Settings{MasterPassword: "orig"})
	_ = ss.save(Settings{MasterPort: 13307}) // 不带密码
	eff, _ := ss.effective()
	if eff.MasterPassword != "orig" {
		t.Errorf("empty password save should keep previous, got %q", eff.MasterPassword)
	}
}
