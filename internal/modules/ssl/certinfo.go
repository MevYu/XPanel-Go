package ssl

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var errNoCert = errors.New("ssl: no certificate in PEM")

// parseCertExpiry 解析 PEM 编码的证书链,返回首个(叶)证书的 NotAfter Unix 秒。
// 用于上传校验与签发/续期后刷新到期时间。
func parseCertExpiry(pemBytes []byte) (int64, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return 0, errNoCert
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, err
		}
		return cert.NotAfter.Unix(), nil
	}
}

// validPrivateKeyPEM 校验上传的私钥是合法 PEM 私钥(不解析具体算法,只确认格式且非证书)。
func validPrivateKeyPEM(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return true
	}
	return false
}
