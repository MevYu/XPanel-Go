package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// loginCookieName 是已登录态存在性凭证 cookie 名。它不替代 Bearer 鉴权,
// 仅供 EntryGate 在普通浏览器跳转/刷新时识别已登录用户、决定 302 重定向而非 404。
const loginCookieName = "xpanel_login"

// loginCookieTTL 与 refresh token 同量级(7 天),过期后凭证失效、回落 404。
const loginCookieTTL = 7 * 24 * time.Hour

// loginCookieKDFLabel 把 JWTSecret 派生成独立的 cookie 签名密钥,
// 使该密钥与 JWT 签名密钥不同源,泄露其一不互相削弱。
const loginCookieKDFLabel = "xpanel-login-cookie-v1"

// loginCookie 用 HMAC-SHA256 签名 "uid:exp" 载荷,只证明"存在有效登录态"。
// 不含敏感明文;签名防伪造;exp 过期失效。
type loginCookie struct {
	key []byte
}

// newLoginCookie 从 JWTSecret 派生独立签名密钥(HMAC-SHA256(secret, label))。
func newLoginCookie(jwtSecret []byte) *loginCookie {
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(loginCookieKDFLabel))
	return &loginCookie{key: mac.Sum(nil)}
}

// sign 返回 "uid:exp:sig" 的 base64url(无填充)载荷。
func (lc *loginCookie) sign(uid int64, exp int64) string {
	payload := strconv.FormatInt(uid, 10) + ":" + strconv.FormatInt(exp, 10)
	sig := lc.mac(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + ":" + sig))
}

func (lc *loginCookie) mac(payload string) string {
	mac := hmac.New(sha256.New, lc.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// set 种登录态 cookie。SameSite=Lax 让普通跳转/刷新带上;Secure 仅在 TLS 请求时置位。
func (lc *loginCookie) set(w http.ResponseWriter, r *http.Request, uid int64) {
	exp := time.Now().Add(loginCookieTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookieName,
		Value:    lc.sign(uid, exp.Unix()),
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(loginCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// clear 以 MaxAge=-1 删除登录态 cookie(logout 调用)。
func (lc *loginCookie) clear(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// verify 校验 cookie 签名与未过期,返回 uid。任何缺失/伪造/过期都返回 ok=false。
func (lc *loginCookie) verify(r *http.Request) (uid int64, ok bool) {
	c, err := r.Cookie(loginCookieName)
	if err != nil {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return 0, false
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 {
		return 0, false
	}
	payload := parts[0] + ":" + parts[1]
	if !hmac.Equal([]byte(lc.mac(payload)), []byte(parts[2])) {
		return 0, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return 0, false
	}
	uid, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return uid, true
}
