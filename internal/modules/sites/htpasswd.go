package sites

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"strings"
)

// PassHasher 抽象口令哈希,便于单测注入确定性盐。默认实现产 apr1(Apache MD5),
// 与 nginx auth_basic / htpasswd 兼容。明文绝不落库,仅存哈希。
type PassHasher interface {
	// Hash 返回 $apr1$salt$digest 形式的哈希。
	Hash(plain string) (string, error)
}

type apr1Hasher struct {
	// salt 生成器,注入便于测试;返回 8 字符 apr1 盐。
	saltFn func(n int) (string, error)
}

func newAPR1Hasher(saltFn func(n int) (string, error)) *apr1Hasher {
	if saltFn == nil {
		saltFn = randSalt
	}
	return &apr1Hasher{saltFn: saltFn}
}

func (h *apr1Hasher) Hash(plain string) (string, error) {
	salt, err := h.saltFn(8)
	if err != nil {
		return "", err
	}
	return apr1(salt, plain), nil
}

const apr1Alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// randSalt 产 n 字符 apr1 盐(取自 apr1 字母表)。
func randSalt(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i := range b {
		out[i] = apr1Alphabet[int(b[i])%len(apr1Alphabet)]
	}
	return string(out), nil
}

// apr1 实现 Apache 的 MD5-crypt($apr1$)。算法与 openssl passwd -apr1 一致。
func apr1(salt, password string) string {
	const magic = "$apr1$"
	pw := []byte(password)
	saltB := []byte(salt)

	// 主摘要 final = md5(pw + magic + salt + md5(pw + salt + pw) 重复填充)
	alt := md5.Sum(append(append(append([]byte{}, pw...), saltB...), pw...))
	d := md5.New()
	d.Write(pw)
	d.Write([]byte(magic))
	d.Write(saltB)
	for i := len(pw); i > 0; i -= 16 {
		if i > 16 {
			d.Write(alt[:16])
		} else {
			d.Write(alt[:i])
		}
	}
	for i := len(pw); i > 0; i >>= 1 {
		if i&1 == 1 {
			d.Write([]byte{0})
		} else {
			d.Write(pw[:1])
		}
	}
	final := d.Sum(nil)

	// 1000 轮加盐重摘要。
	for i := 0; i < 1000; i++ {
		c := md5.New()
		if i&1 == 1 {
			c.Write(pw)
		} else {
			c.Write(final)
		}
		if i%3 != 0 {
			c.Write(saltB)
		}
		if i%7 != 0 {
			c.Write(pw)
		}
		if i&1 == 1 {
			c.Write(final)
		} else {
			c.Write(pw)
		}
		final = c.Sum(nil)
	}

	return magic + salt + "$" + apr1Encode(final)
}

// apr1Encode 是 apr1 特有的 base64 重排+编码。
func apr1Encode(final []byte) string {
	var sb strings.Builder
	to64 := func(v uint, n int) {
		for ; n > 0; n-- {
			sb.WriteByte(apr1Alphabet[v&0x3f])
			v >>= 6
		}
	}
	to64(uint(final[0])<<16|uint(final[6])<<8|uint(final[12]), 4)
	to64(uint(final[1])<<16|uint(final[7])<<8|uint(final[13]), 4)
	to64(uint(final[2])<<16|uint(final[8])<<8|uint(final[14]), 4)
	to64(uint(final[3])<<16|uint(final[9])<<8|uint(final[15]), 4)
	to64(uint(final[4])<<16|uint(final[10])<<8|uint(final[5]), 4)
	to64(uint(final[11]), 2)
	return sb.String()
}

// htpasswdLine 组装一行 .htpasswd 记录。
func htpasswdLine(username, hash string) string {
	return fmt.Sprintf("%s:%s\n", username, hash)
}

// htpasswdFile 把同目录的多条保护项渲染成 .htpasswd 文件内容。
func htpasswdFile(entries []DirProtect) string {
	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString(htpasswdLine(e.Username, e.PassHash))
	}
	return sb.String()
}
