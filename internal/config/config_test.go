package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	c1, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	b, err := c1.DecodedSecret()
	if err != nil {
		t.Fatalf("DecodedSecret: %v", err)
	}
	if len(b) < 32 {
		t.Error("decoded JWT secret should be >=32 bytes")
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("config file should be persisted on first load")
	}

	// 二次加载读回同一密钥
	c2, _ := Load(path)
	if c1.JWTSecret != c2.JWTSecret {
		t.Error("JWT secret must be stable across loads")
	}
}

func TestGeneratedDefaultsAndEntryPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.LoginMaxAttempts != 3 {
		t.Errorf("login_max_attempts default = %d, want 3", c.LoginMaxAttempts)
	}
	if c.IPBanHours != 72 {
		t.Errorf("ip_ban_hours default = %d, want 72", c.IPBanHours)
	}
	// entry_path = "/" + 16 hex chars.
	if len(c.EntryPath) != 17 || c.EntryPath[0] != '/' {
		t.Fatalf("entry_path = %q, want /<16 hex>", c.EntryPath)
	}

	// 稳定:二次加载读回同一 entry_path。
	c2, _ := Load(path)
	if c2.EntryPath != c.EntryPath {
		t.Errorf("entry_path must be stable across loads: %q != %q", c.EntryPath, c2.EntryPath)
	}
}

// 老配置(缺新字段)加载时应补默认并回写持久化。
func TestLoadBackfillsDefaultsForOldConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	old := `{"addr":"127.0.0.1:8765","db_path":"data/xpanel.db","jwt_secret":"` +
		base64FixedSecret + `"}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.LoginMaxAttempts != 3 || c.IPBanHours != 72 || c.EntryPath == "" {
		t.Fatalf("defaults not backfilled: %+v", c)
	}
	// 回写后再读 entry_path 稳定。
	c2, _ := Load(path)
	if c2.EntryPath != c.EntryPath {
		t.Errorf("backfilled entry_path must persist: %q != %q", c.EntryPath, c2.EntryPath)
	}
}

// 48 字节全零的 base64,满足 >=32 字节长度校验。
const base64FixedSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestLoadRejectsInvalidSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"addr":"127.0.0.1:8765","db_path":"data/xpanel.db","jwt_secret":""}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load should reject empty/invalid jwt_secret")
	}
}
