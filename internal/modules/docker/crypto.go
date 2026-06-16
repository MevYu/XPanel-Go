package docker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// Registry 凭证(密码/token)必须 AES-GCM 加密落库,绝不明文、绝不进日志。
// 密钥从模块自建的 per-install secret 派生(SHA-256 → 32 字节 AES-256 key)。
// secret 首次使用时随机生成并持久化在 docker_settings 表里。

var errDecrypt = errors.New("decrypt failed")

// cryptor 用一把派生密钥做 AES-GCM 加解密。
type cryptor struct{ gcm cipher.AEAD }

// newCryptor 由任意长度 secret 派生 AES-256-GCM。
func newCryptor(secret string) (*cryptor, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &cryptor{gcm: gcm}, nil
}

// encrypt 返回 base64(nonce||ciphertext)。空明文返回空串。
func (c *cryptor) encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := c.gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// decrypt 还原 encrypt 的输出。空串还原为空串。
func (c *cryptor) decrypt(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", errDecrypt
	}
	ns := c.gcm.NonceSize()
	if len(raw) < ns {
		return "", errDecrypt
	}
	nonce, ct := raw[:ns], raw[ns:]
	plain, err := c.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", errDecrypt
	}
	return string(plain), nil
}

// newInstallSecret 生成 32 字节随机密钥的 base64 串,用作 per-install 加密 secret。
func newInstallSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
