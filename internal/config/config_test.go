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
	if len(c1.JWTSecret) < 32 {
		t.Error("JWT secret should be >=32 bytes")
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
