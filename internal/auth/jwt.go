package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// accessTTL 短时效;撤销靠 refresh token,access 过期即失效。
const accessTTL = 15 * time.Minute

// Claims 是 access token 的载荷,内嵌标准 RegisteredClaims。
type Claims struct {
	UserID int64  `json:"uid"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// JWTManager 用对称密钥签发与校验 HS256 access token。
type JWTManager struct {
	secret []byte
}

// NewJWTManager 返回以 secret 为签名密钥的 JWTManager。
func NewJWTManager(secret []byte) *JWTManager {
	return &JWTManager{secret: secret}
}

func (m *JWTManager) Issue(userID int64, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

// Parse 校验签名与过期;只接受 HS256,防 alg=none 与其他 alg 降级攻击。
func (m *JWTManager) Parse(token string) (*Claims, error) {
	var claims Claims
	_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return m.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	return &claims, nil
}
