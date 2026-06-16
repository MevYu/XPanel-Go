package server

import (
	"encoding/json"
	"net/http"

	"github.com/MevYu/XPanel-Go/internal/auth"
)

// loginTOTPVerifier 校验某用户登录时的 2FA。enabled 表示该用户是否启用 2FA,
// ok 表示提供的 code 是否通过。宿主注入以避免 server 直接依赖 users 内部细节。
type loginTOTPVerifier func(userID int64, code string) (enabled, ok bool, err error)

type authHandlers struct {
	svc *auth.Service
	// totp 为登录时的 2FA 校验器;nil 表示不启用登录 2FA 门(如基础 server.New)。
	totp loginTOTPVerifier
	// clientIP 提取真实客户端 IP(受信代理感知),供锁定/封禁/审计统一取 IP。
	clientIP func(*http.Request) string
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp"` // 可选;用户启用 2FA 时必填的 6 位码
}

type tokenResp struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

func (a *authHandlers) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip := a.clientIP(r)
	u, err := a.svc.VerifyPassword(req.Username, req.Password, ip)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// 密码已对(锁定已 Reset)。2FA 缺失/错误不计入锁定,避免锁死正常用户。
	if a.totp != nil {
		enabled, ok, verr := a.totp(u.ID, req.TOTP)
		if verr != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if enabled && !ok {
			a.svc.Audit(&u.ID, "login.2fa_required", "", ip)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "2fa_required"})
			return
		}
	}
	a.svc.Audit(&u.ID, "login.success", "", ip)
	tok, err := a.svc.IssueFor(u.ID, u.Role)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, tokenResp{tok.Access, tok.Refresh})
}

type refreshReq struct {
	Refresh string `json:"refresh"`
}

func (a *authHandlers) refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip := a.clientIP(r)
	tok, err := a.svc.Refresh(req.Refresh, ip)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, tokenResp{tok.Access, tok.Refresh})
}

func (a *authHandlers) logout(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip := a.clientIP(r)
	// 忽略错误:logout 幂等,且不泄露 token 是否存在。
	_ = a.svc.Logout(req.Refresh, ip)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
