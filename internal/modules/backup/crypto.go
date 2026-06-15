package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// 远端凭证(rclone remote 的 access key / secret 等)必须 AES-GCM 加密落库,
// 绝不明文、绝不进日志。密钥从面板进程注入的 secret 派生(SHA-256 → AES-256)。

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

// encrypt 返回 base64(nonce||ciphertext)。空明文返回空串(表示"无凭证")。
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
