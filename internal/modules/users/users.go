// Package users 实现多用户管理模块:用户增删改/改角色/重置密码(admin),
// 当前用户的 TOTP 2FA 密钥生命周期与校验,以及 API Key 的创建/列出/吊销。
// 登录时强制 2FA 由宿主单独集成,本模块只负责密钥生命周期与校验端点。
package users

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"

	"github.com/pquerna/otp/totp"
)

// Deps 注入宿主能力,避免反向依赖 server。与其他模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的用户管理模块。
type Module struct {
	us   *userStore
	box  *secretBox
	deps Deps
}

const (
	settingTOTPIssuer = "totp_issuer"
	defaultTOTPIssuer = "XPanel"
)

// New 建表并返回模块。secret 用于派生 TOTP 密钥的 AES-GCM 加密密钥。
// 建表失败(DB 不可用)直接 panic:模块无法工作。
func New(st *store.Store, secret string, deps Deps) *Module {
	us, err := newUserStore(st)
	if err != nil {
		panic("users: init store: " + err.Error())
	}
	return &Module{us: us, box: newSecretBox(secret), deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "users", Name: "用户", Category: "安全"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "用户", Icon: "users", Path: "/users"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:纯 DB 模块,无外部依赖。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	// 用户管理:全部需 admin。
	r.Get("/users", m.handleListUsers)
	r.Post("/users", m.handleCreateUser)
	r.Delete("/users/{id}", m.handleDeleteUser)
	r.Put("/users/{id}/role", m.handleSetRole)
	r.Post("/users/{id}/reset-password", m.handleResetPassword)

	// 2FA:作用于当前登录用户自己。
	r.Post("/2fa/setup", m.handleTOTPSetup)
	r.Post("/2fa/verify", m.handleTOTPVerify)
	r.Post("/2fa/disable", m.handleTOTPDisable)

	// API Key:作用于当前登录用户自己。
	r.Get("/api-keys", m.handleListAPIKeys)
	r.Post("/api-keys", m.handleCreateAPIKey)
	r.Delete("/api-keys/{id}", m.handleRevokeAPIKey)

	// 可配置项:admin。
	r.Get("/settings", m.handleGetSettings)
	r.Put("/settings", m.handlePutSettings)
}

// --- 用户管理(admin) ---

func (m *Module) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	users, err := m.us.listUsers()
	if err != nil {
		log.Printf("users: list failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []UserInfo{}
	}
	writeJSON(w, http.StatusOK, users)
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (m *Module) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req createUserRequest
	if !decode(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !validUsername(req.Username) {
		http.Error(w, "invalid username (3-32 chars, alnum/_/-/.)", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		http.Error(w, "password too short (min 8)", http.StatusBadRequest)
		return
	}
	if !validRole(req.Role) {
		http.Error(w, "invalid role (admin|operator|readonly)", http.StatusBadRequest)
		return
	}
	taken, err := m.us.usernameTaken(req.Username)
	if err != nil {
		log.Printf("users: username check failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	if taken {
		http.Error(w, "username already exists", http.StatusConflict)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("users: hash failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	id, err := m.us.createUser(req.Username, hash, req.Role)
	if err != nil {
		log.Printf("users: create failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "users.create", req.Username+" role="+req.Role, m.clientIP(r))
	writeJSON(w, http.StatusCreated, UserInfo{
		ID: id, Username: req.Username, Role: req.Role,
	})
}

func (m *Module) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if id == uid {
		http.Error(w, "cannot delete yourself", http.StatusBadRequest)
		return
	}
	exists, err := m.us.userExists(id)
	if err != nil {
		log.Printf("users: exists check failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if ok, err := m.guardLastAdmin(w, id, ""); err != nil || !ok {
		return
	}
	if err := m.us.deleteUser(id); err != nil {
		log.Printf("users: delete failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "users.delete", strconv.FormatInt(id, 10), m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

type roleRequest struct {
	Role string `json:"role"`
}

func (m *Module) handleSetRole(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req roleRequest
	if !decode(w, r, &req) {
		return
	}
	if !validRole(req.Role) {
		http.Error(w, "invalid role (admin|operator|readonly)", http.StatusBadRequest)
		return
	}
	exists, err := m.us.userExists(id)
	if err != nil {
		log.Printf("users: exists check failed: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	// 降级最后一个 admin 会锁死系统。
	if req.Role != "admin" {
		if ok, err := m.guardLastAdmin(w, id, req.Role); err != nil || !ok {
			return
		}
	}
	if err := m.us.setRole(id, req.Role); err != nil {
		log.Printf("users: set role failed: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "users.set_role", strconv.FormatInt(id, 10)+" -> "+req.Role, m.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "role": req.Role})
}

type passwordRequest struct {
	Password string `json:"password"`
}

func (m *Module) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req passwordRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Password) < 8 {
		http.Error(w, "password too short (min 8)", http.StatusBadRequest)
		return
	}
	exists, err := m.us.userExists(id)
	if err != nil {
		log.Printf("users: exists check failed: %v", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("users: hash failed: %v", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	if err := m.us.setPassword(id, hash); err != nil {
		log.Printf("users: reset password failed: %v", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "users.reset_password", strconv.FormatInt(id, 10), m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// --- 2FA(当前用户) ---

type totpSetupResponse struct {
	Secret     string `json:"secret"`      // base32 明文,只返回一次
	OTPAuthURL string `json:"otpauth_url"` // otpauth:// URL,只返回一次
}

// handleTOTPSetup 为当前用户生成新的 TOTP 密钥(加密落库,enabled=false),返回明文密钥+URL。
// 已启用 2FA 的用户重新 setup 会覆盖旧密钥并需重新 verify。
func (m *Module) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	uid, _ := m.deps.Principal(r)
	issuer, err := m.us.getSetting(settingTOTPIssuer, defaultTOTPIssuer)
	if err != nil {
		log.Printf("users: read issuer failed: %v", err)
		http.Error(w, "setup failed", http.StatusInternalServerError)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: "user-" + strconv.FormatInt(uid, 10),
	})
	if err != nil {
		log.Printf("users: totp generate failed: %v", err)
		http.Error(w, "setup failed", http.StatusInternalServerError)
		return
	}
	enc, err := m.box.encrypt([]byte(key.Secret()))
	if err != nil {
		log.Printf("users: encrypt secret failed: %v", err)
		http.Error(w, "setup failed", http.StatusInternalServerError)
		return
	}
	if err := m.us.upsertTOTP(uid, enc, false); err != nil {
		log.Printf("users: store totp failed: %v", err)
		http.Error(w, "setup failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "users.2fa.setup", "", m.clientIP(r))
	writeJSON(w, http.StatusOK, totpSetupResponse{Secret: key.Secret(), OTPAuthURL: key.URL()})
}

type totpVerifyRequest struct {
	Code string `json:"code"`
}

// handleTOTPVerify 校验 6 位码并启用 2FA。需先 setup。
func (m *Module) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	uid, _ := m.deps.Principal(r)
	var req totpVerifyRequest
	if !decode(w, r, &req) {
		return
	}
	code := strings.TrimSpace(req.Code)
	row, err := m.us.getTOTP(uid)
	if errors.Is(err, errNotFound) {
		http.Error(w, "no pending 2fa setup", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("users: get totp failed: %v", err)
		http.Error(w, "verify failed", http.StatusInternalServerError)
		return
	}
	secret, err := m.box.decrypt(row.SecretEnc)
	if err != nil {
		log.Printf("users: decrypt secret failed for user %d: %v", uid, err)
		http.Error(w, "verify failed", http.StatusInternalServerError)
		return
	}
	if !totp.Validate(code, string(secret)) {
		m.deps.Audit(&uid, "users.2fa.verify", "invalid", m.clientIP(r))
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	if err := m.us.setTOTPEnabled(uid, true); err != nil {
		log.Printf("users: enable totp failed: %v", err)
		http.Error(w, "verify failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "users.2fa.verify", "enabled", m.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true})
}

// handleTOTPDisable 关闭并删除当前用户的 TOTP 密钥。
func (m *Module) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	uid, _ := m.deps.Principal(r)
	if err := m.us.deleteTOTP(uid); err != nil {
		log.Printf("users: disable totp failed: %v", err)
		http.Error(w, "disable failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "users.2fa.disable", "", m.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

// --- API Key(当前用户) ---

func (m *Module) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	uid, _ := m.deps.Principal(r)
	keys, err := m.us.listAPIKeys(uid)
	if err != nil {
		log.Printf("users: list api keys failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []APIKeyInfo{}
	}
	writeJSON(w, http.StatusOK, keys)
}

type apiKeyRequest struct {
	Name string `json:"name"`
}

type apiKeyCreateResponse struct {
	APIKeyInfo
	Key string `json:"key"` // 明文,只返回一次
}

func (m *Module) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	uid, _ := m.deps.Principal(r)
	var req apiKeyRequest
	if !decode(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) > 64 {
		http.Error(w, "name too long (max 64)", http.StatusBadRequest)
		return
	}
	plain, hash, err := generateAPIKey()
	if err != nil {
		log.Printf("users: generate api key failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	id, err := m.us.createAPIKey(uid, name, hash)
	if err != nil {
		log.Printf("users: store api key failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "users.apikey.create", strconv.FormatInt(id, 10)+" "+name, m.clientIP(r))
	writeJSON(w, http.StatusCreated, apiKeyCreateResponse{
		APIKeyInfo: APIKeyInfo{ID: id, UserID: uid, Name: name},
		Key:        plain,
	})
}

func (m *Module) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	uid, _ := m.deps.Principal(r)
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	hit, err := m.us.revokeAPIKey(uid, id)
	if err != nil {
		log.Printf("users: revoke api key failed: %v", err)
		http.Error(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	if !hit {
		http.Error(w, "api key not found", http.StatusNotFound)
		return
	}
	m.deps.Audit(&uid, "users.apikey.revoke", strconv.FormatInt(id, 10), m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// --- settings(admin) ---

type settingsBody struct {
	TOTPIssuer string `json:"totp_issuer"`
}

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	issuer, err := m.us.getSetting(settingTOTPIssuer, defaultTOTPIssuer)
	if err != nil {
		log.Printf("users: get settings failed: %v", err)
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, settingsBody{TOTPIssuer: issuer})
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req settingsBody
	if !decode(w, r, &req) {
		return
	}
	issuer := strings.TrimSpace(req.TOTPIssuer)
	if issuer == "" || len(issuer) > 64 {
		http.Error(w, "invalid totp_issuer (1-64 chars)", http.StatusBadRequest)
		return
	}
	if err := m.us.setSetting(settingTOTPIssuer, issuer); err != nil {
		log.Printf("users: set settings failed: %v", err)
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "users.settings.update", "totp_issuer="+issuer, m.clientIP(r))
	writeJSON(w, http.StatusOK, settingsBody{TOTPIssuer: issuer})
}

// --- helpers ---

// requireAdmin 校验 admin 角色。失败时已写 403,返回 ok=false。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// guardLastAdmin 阻止删除/降级最后一个 admin。目标本身不是 admin 时直接放行。
// newRole 为空表示删除场景。失败时已写响应,返回 ok=false。
func (m *Module) guardLastAdmin(w http.ResponseWriter, targetID int64, newRole string) (bool, error) {
	role, err := m.us.getRole(targetID)
	if err != nil {
		log.Printf("users: get role failed: %v", err)
		http.Error(w, "operation failed", http.StatusInternalServerError)
		return false, err
	}
	if role != "admin" {
		return true, nil
	}
	n, err := m.us.countAdmins()
	if err != nil {
		log.Printf("users: count admins failed: %v", err)
		http.Error(w, "operation failed", http.StatusInternalServerError)
		return false, err
	}
	if n <= 1 {
		http.Error(w, "cannot remove the last admin", http.StatusBadRequest)
		return false, nil
	}
	return true, nil
}

func validUsername(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '.':
		default:
			return false
		}
	}
	return true
}

func validRole(role string) bool {
	switch role {
	case "admin", "operator", "readonly":
		return true
	}
	return false
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := chi.URLParamFromCtx(r.Context(), "id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP 取真实客户端 IP:有受信代理感知的提取器则用之,否则回退 RemoteAddr。
func (m *Module) clientIP(r *http.Request) string {
	if m.deps.ClientIP != nil {
		return m.deps.ClientIP(r)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
