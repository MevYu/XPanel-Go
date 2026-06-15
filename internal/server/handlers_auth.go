package server

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/MevYu/XPanel-Go/internal/auth"
)

type authHandlers struct {
	svc *auth.Service
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
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
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	tok, err := a.svc.Login(req.Username, req.Password, ip)
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
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
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
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	// 忽略错误:logout 幂等,且不泄露 token 是否存在。
	_ = a.svc.Logout(req.Refresh, ip)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
