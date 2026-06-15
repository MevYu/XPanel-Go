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
