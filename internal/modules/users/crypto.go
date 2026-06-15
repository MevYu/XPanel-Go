package users

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// errDecrypt 解密失败(密文损坏、密钥不符、长度不足)统一返回,不泄露细节。
var errDecrypt = errors.New("users: decrypt failed")

// secretBox 用从宿主 secret 派生的 32 字节密钥做 AES-256-GCM 加解密,
// 用于落库的 TOTP 密钥。每次加密随机 nonce,密文格式 base64(nonce||ciphertext)。
type secretBox struct{ aead cipher.AEAD }

// newSecretBox 从任意长度 secret 用 SHA-256 派生固定 32 字节 AES 密钥。
func newSecretBox(secret string) *secretBox {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		// SHA-256 恒为 32 字节,AES-256 必然成功;走到这里说明 crypto 损坏。
		panic("users: aes init: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("users: gcm init: " + err.Error())
	}
	return &secretBox{aead: aead}
}

// encrypt 返回 base64(nonce||ciphertext)。
func (b *secretBox) encrypt(plain []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := b.aead.Seal(nonce, nonce, plain, nil)
	return base64.RawStdEncoding.EncodeToString(ct), nil
}

// decrypt 还原 encrypt 的输出。任何失败返回 errDecrypt。
func (b *secretBox) decrypt(encoded string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errDecrypt
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return nil, errDecrypt
	}
	plain, err := b.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return nil, errDecrypt
	}
	return plain, nil
}

// apiKeyBytes 是明文 API Key 的随机字节数(返回给用户的是 base64url)。
const apiKeyBytes = 32

// generateAPIKey 生成明文 key 与其 SHA-256 哈希(hex)。明文只返回一次,落库存哈希。
func generateAPIKey() (plain, hash string, err error) {
	b := make([]byte, apiKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	plain = "xpk_" + base64.RawURLEncoding.EncodeToString(b)
	hash = hashAPIKey(plain)
	return plain, hash, nil
}

// hashAPIKey 对明文 key 做 SHA-256 并 hex 编码。key 是高熵随机串,无需加盐慢哈希。
func hashAPIKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return fmt.Sprintf("%x", sum)
}

// apiKeyMatches 常数时间比较明文 key 与存储哈希。
func apiKeyMatches(plain, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(hashAPIKey(plain)), []byte(storedHash)) == 1
}
