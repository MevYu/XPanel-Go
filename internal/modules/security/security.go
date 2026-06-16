package security

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server。与其他模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的安全加固模块。ssh/f2b/loglib 三个后端可注入,便于 mock 测。
type Module struct {
	st     *secStore
	ssh    SSHControl
	f2b    Fail2ban
	loglib LoginLog
	deps   Deps
}

// New 建表并返回模块。后端传 nil 时用真实 exec 实现。建表失败 panic:模块无法工作。
func New(st *store.Store, ssh SSHControl, f2b Fail2ban, loglib LoginLog, deps Deps) *Module {
	ss, err := newSecStore(st)
	if err != nil {
		panic("security: init store: " + err.Error())
	}
	if ssh == nil {
		ssh = NewSSHControl()
	}
	if f2b == nil {
		f2b = NewFail2ban()
	}
	if loglib == nil {
		loglib = NewLoginLog()
	}
	return &Module{st: ss, ssh: ssh, f2b: f2b, loglib: loglib, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "security", Name: "安全加固", Category: "安全"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "安全加固", Icon: "shield-lock", Path: "/security"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:sshd 不在则不允许启用(SSH 加固是核心能力)。
func (m *Module) HealthCheck() error { return m.ssh.Available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // admin:读可配置路径
	r.Put("/settings", m.handlePutSettings) // admin:改可配置路径

	r.Get("/sshd", m.handleSSHDGet)            // admin:读白名单指令当前值
	r.Put("/sshd", m.handleSSHDSet)            // admin:改单条指令(危险键需确认)
	r.Post("/sshd/reload", m.handleSSHDReload) // admin:sshd -t 通过后 reload

	r.Get("/keys", m.handleKeysList)           // admin:列 authorized_keys
	r.Post("/keys", m.handleKeysAdd)           // admin:加公钥
	r.Delete("/keys/{id}", m.handleKeysDelete) // admin:删公钥

	r.Get("/fail2ban/status", m.handleF2bStatus) // admin:状态
	r.Get("/fail2ban/banned", m.handleF2bBanned) // admin:被封 IP
	r.Post("/fail2ban/unban", m.handleF2bUnban)  // admin:解封(危险)
	r.Post("/fail2ban/jail", m.handleF2bJail)    // admin:jail 启停(停为危险)

	r.Get("/logins", m.handleLogins) // admin:登录日志(成功/失败)
}

// requireAdmin 取主体并强制 admin;非 admin 返回 (0,"",false) 并已写 403。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	st, err := m.st.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var st Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&st); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// 路径须绝对,避免相对路径误指。
	if !strings.HasPrefix(st.SSHDConfigPath, "/") ||
		!strings.HasPrefix(st.Fail2banConfigDir, "/") ||
		!strings.HasPrefix(st.AuthorizedKeys, "/") {
		http.Error(w, "paths must be absolute", http.StatusBadRequest)
		return
	}
	if err := m.st.putSettings(st); err != nil {
		http.Error(w, "failed to save settings", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "security.settings.update", "paths updated", m.clientIP(r))
	writeJSON(w, http.StatusOK, st)
}

func (m *Module) handleSSHDGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	st, err := m.st.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	dirs, err := m.ssh.ReadDirectives(st.SSHDConfigPath)
	if err != nil {
		log.Printf("security: read sshd_config failed: %v", err)
		http.Error(w, "sshd_config unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, dirs)
}

type sshdSetReq struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (m *Module) handleSSHDSet(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req sshdSetReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// 白名单 + 取值校验:非法即拒,绝不落盘。
	if err := ValidateSSHDirective(req.Key, req.Value); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// 危险键(改端口/禁密码/禁公钥/改 root 登录)须二次确认。
	if SSHKeyDangerous(req.Key) && !confirmed(r) {
		http.Error(w, "dangerous directive requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	st, err := m.st.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	backup, err := m.ssh.SetDirective(st.SSHDConfigPath, req.Key, req.Value)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "security.sshd.set", req.Key+"="+req.Value+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("security: set sshd %s failed: %v", req.Key, err)
		http.Error(w, "sshd_config update failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "backup": backup})
}

func (m *Module) handleSSHDReload(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	st, err := m.st.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	// reload 前再校验一次,坏配置绝不重载。
	if err := m.ssh.Validate(st.SSHDConfigPath); err != nil {
		m.deps.Audit(&uid, "security.sshd.reload", "validate failed", m.clientIP(r))
		http.Error(w, "sshd config validation failed", http.StatusConflict)
		return
	}
	err = m.ssh.Reload()
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "security.sshd.reload", outcome, m.clientIP(r))
	if err != nil {
		log.Printf("security: reload sshd failed: %v", err)
		http.Error(w, "sshd reload failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (m *Module) handleKeysList(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	keys, err := m.st.listKeys()
	if err != nil {
		http.Error(w, "failed to list keys", http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []SSHKey{}
	}
	writeJSON(w, http.StatusOK, keys)
}

type keyAddReq struct {
	Comment   string `json:"comment"`
	PublicKey string `json:"public_key"`
}

func (m *Module) handleKeysAdd(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req keyAddReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	norm, err := ValidatePublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	st, err := m.st.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	if err := AddAuthorizedKey(st.AuthorizedKeys, norm); err != nil {
		log.Printf("security: add authorized key failed: %v", err)
		http.Error(w, "failed to write authorized_keys", http.StatusInternalServerError)
		return
	}
	id, err := m.st.addKey(req.Comment, norm, &uid)
	if err != nil {
		log.Printf("security: persist key metadata failed: %v", err)
		http.Error(w, "failed to persist key", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "security.key.add", req.Comment, m.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]int64{"id": id})
}

func (m *Module) handleKeysDelete(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(chi.URLParamFromCtx(r.Context(), "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	key, err := m.st.getKey(id)
	if err != nil {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}
	st, err := m.st.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	if err := RemoveAuthorizedKey(st.AuthorizedKeys, key.PublicKey); err != nil {
		log.Printf("security: remove authorized key failed: %v", err)
		http.Error(w, "failed to update authorized_keys", http.StatusInternalServerError)
		return
	}
	if err := m.st.deleteKey(id); err != nil {
		http.Error(w, "failed to delete key", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "security.key.delete", key.Comment, m.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (m *Module) handleF2bStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	out, err := m.f2b.Status(jailParam(r))
	if err != nil {
		log.Printf("security: fail2ban status failed: %v", err)
		http.Error(w, "fail2ban unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (m *Module) handleF2bBanned(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	jail := jailParam(r)
	if !validJailName(jail) {
		http.Error(w, "invalid jail name", http.StatusBadRequest)
		return
	}
	ips, err := m.f2b.Banned(jail)
	if err != nil {
		log.Printf("security: fail2ban banned failed: %v", err)
		http.Error(w, "fail2ban unavailable", http.StatusInternalServerError)
		return
	}
	if ips == nil {
		ips = []string{}
	}
	writeJSON(w, http.StatusOK, ips)
}

type f2bUnbanReq struct {
	Jail string `json:"jail"`
	IP   string `json:"ip"`
}

// handleF2bUnban 解封属危险操作(放回潜在攻击者):需二次确认。
func (m *Module) handleF2bUnban(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	var req f2bUnbanReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !validJailName(req.Jail) {
		http.Error(w, "invalid jail name", http.StatusBadRequest)
		return
	}
	if net.ParseIP(req.IP) == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	err := m.f2b.Unban(req.Jail, req.IP)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "security.fail2ban.unban", req.Jail+"/"+req.IP+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("security: fail2ban unban failed: %v", err)
		http.Error(w, "fail2ban operation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type f2bJailReq struct {
	Jail   string `json:"jail"`
	Enable bool   `json:"enable"`
}

// handleF2bJail 启停 jail:停用 jail 会撤掉保护,属危险操作,需二次确认。
func (m *Module) handleF2bJail(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req f2bJailReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !validJailName(req.Jail) {
		http.Error(w, "invalid jail name", http.StatusBadRequest)
		return
	}
	if !req.Enable && !confirmed(r) {
		http.Error(w, "stopping a jail requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	err := m.f2b.SetJail(req.Jail, req.Enable)
	action := "security.fail2ban.jail.stop"
	if req.Enable {
		action = "security.fail2ban.jail.start"
	}
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, action, req.Jail+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("security: fail2ban jail %s failed: %v", req.Jail, err)
		http.Error(w, "fail2ban operation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (m *Module) handleLogins(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	failed := r.URL.Query().Get("failed") == "true"
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	entries, err := m.loglib.Recent(failed, limit)
	if err != nil {
		log.Printf("security: read login log failed: %v", err)
		http.Error(w, "login log unavailable", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []LoginEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// ---- helpers ----

func jailParam(r *http.Request) string { return r.URL.Query().Get("jail") }

// jailNameRe 要求 jail 名首字符为字母/数字/下划线,杜绝 "-" 开头被 fail2ban-client
// 当成 flag(如 "--help")造成的参数注入。
var jailNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)

// validJailName 限制 jail 名为安全字符且不以 "-" 开头(防参数注入)。
func validJailName(s string) bool {
	if s == "" {
		return true // 空表示总览,合法
	}
	return len(s) <= 64 && jailNameRe.MatchString(s)
}

// confirmed 检查危险操作的二次确认标记。
func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

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
