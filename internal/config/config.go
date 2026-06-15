package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type Config struct {
	Addr      string `json:"addr"`       // 监听地址,默认 127.0.0.1:8765(不绑 0.0.0.0)
	DBPath    string `json:"db_path"`    // SQLite 文件路径
	JWTSecret string `json:"jwt_secret"` // base64,首启随机生成
}

// Load 读配置文件;不存在则用安全默认值生成并持久化。
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return generate(path)
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}
	if _, err := c.DecodedSecret(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// DecodedSecret 解码 JWT 密钥并校验长度,确保签名密钥有效(防被改坏的 config 导致弱/空密钥)。
func (c Config) DecodedSecret() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(c.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("decode jwt_secret: %w", err)
	}
	if len(b) < 32 {
		return nil, errors.New("jwt_secret too short (need >= 32 bytes)")
	}
	return b, nil
}

func generate(path string) (Config, error) {
	secret := make([]byte, 48)
	if _, err := rand.Read(secret); err != nil {
		return Config{}, err
	}
	c := Config{
		Addr:      "127.0.0.1:8765",
		DBPath:    "data/xpanel.db",
		JWTSecret: base64.StdEncoding.EncodeToString(secret),
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return Config{}, err
	}
	return c, nil
}
