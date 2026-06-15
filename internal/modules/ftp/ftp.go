// Package ftp 实现 FTP 账户管理模块(对标 aaPanel FTP):列出/创建/删除/改密/启停
// 虚拟用户。优先适配 pure-ftpd 虚拟用户(pure-pw),把服务操作抽象成 ftpBackend 接口
// 便于 mock 测试。口令绝不明文落 XPanel 的库 —— 经 stdin 交给后端,由后端自身哈希存储。
// 家目录/配置路径可配置并持久化;用户名与路径严格白名单;删除等危险操作需 X-Confirm-Danger。
package ftp

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
}

// Module 是可开关的 FTP 账户管理模块。
type Module struct {
	ss   *settingsStore
	be   ftpBackend
	deps Deps
}

// New 建表并返回模块。建表失败直接 panic:模块无法工作。
// be 为 nil 时用默认 pure-ftpd 后端(uid/gid 取当前有效设置)。
func New(st *store.Store, be ftpBackend, deps Deps) *Module {
	ss, err := newSettingsStore(st)
	if err != nil {
		panic("ftp: init store: " + err.Error())
	}
	if be == nil {
		eff, err := ss.effective()
		if err != nil {
			panic("ftp: load settings: " + err.Error())
		}
		be = newPureFTPd(eff.VirtualUID, eff.VirtualGID)
	}
	return &Module{ss: ss, be: be, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "ftp", Name: "FTP", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "FTP", Icon: "folder-symlink", Path: "/ftp"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:FTP 后端(pure-ftpd/vsftpd)不在则不允许启用。
func (m *Module) HealthCheck() error { return m.be.available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // 只读(admin)
	r.Put("/settings", m.handlePutSettings) // 写(admin)

	r.Get("/accounts", m.handleList)                                 // 列出(admin)
	r.Post("/accounts", m.handleCreate)                              // 创建(admin)
	r.Delete("/accounts/{user}", m.handleDelete)                     // 删除(admin + 危险确认)
	r.Post("/accounts/{user}/password", m.handlePassword)            // 改密(admin)
	r.Post("/accounts/{user}/{verb:enable|disable}", m.handleToggle) // 启停(admin)
}

// accountRequest 是创建账户的请求体。Home 为空则用 HomeBase/<user>。
type accountRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Home     string `json:"home"`
	Readonly bool   `json:"readonly"`
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) {
	if !m.requireAdmin(w, r) {
		return
	}
	metas, err := m.ss.listAccounts()
	if err != nil {
		log.Printf("ftp: list accounts failed: %v", err)
		http.Error(w, "accounts unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": orEmpty(metas)})
}

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var req accountRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validUser(req.User) {
		http.Error(w, errInvalidUser.Error(), http.StatusBadRequest)
		return
	}
	if !validPassword(req.Password) {
		http.Error(w, errInvalidPassword.Error(), http.StatusBadRequest)
		return
	}
	eff, err := m.ss.effective()
	if err != nil {
		log.Printf("ftp: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	home := req.Home
	if home == "" {
		home = eff.HomeBase + "/" + req.User
	}
	home, err = resolveHome(eff.HomeBase, home)
	if err != nil {
		http.Error(w, errInvalidHome.Error(), http.StatusBadRequest)
		return
	}

	cerr := m.be.create(r.Context(), req.User, req.Password, home, req.Readonly)
	outcome := "ok"
	if cerr != nil {
		outcome = "failed"
	}
	// 审计 detail 绝不含口令,仅用户名/路径/权限。
	m.deps.Audit(&uid, "ftp.account.create", "user="+req.User+" home="+home+" "+outcome, clientIP(r))
	if cerr != nil {
		log.Printf("ftp: create %q failed: %v", req.User, cerr)
		http.Error(w, "ftp account create failed", http.StatusBadGateway)
		return
	}
	if err := m.ss.upsertAccount(acctMeta{User: req.User, Home: home, Readonly: req.Readonly, Enabled: true}); err != nil {
		log.Printf("ftp: persist account meta failed: %v", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	user := chi.URLParamFromCtx(r.Context(), "user")
	if !validUser(user) {
		http.Error(w, errInvalidUser.Error(), http.StatusBadRequest)
		return
	}
	derr := m.be.delete(r.Context(), user)
	outcome := "ok"
	if derr != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "ftp.account.delete", "user="+user+" "+outcome, clientIP(r))
	if derr != nil {
		log.Printf("ftp: delete %q failed: %v", user, derr)
		http.Error(w, "ftp account delete failed", http.StatusBadGateway)
		return
	}
	if err := m.ss.deleteAccount(user); err != nil {
		log.Printf("ftp: delete account meta failed: %v", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handlePassword(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	user := chi.URLParamFromCtx(r.Context(), "user")
	if !validUser(user) {
		http.Error(w, errInvalidUser.Error(), http.StatusBadRequest)
		return
	}
	var req accountRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validPassword(req.Password) {
		http.Error(w, errInvalidPassword.Error(), http.StatusBadRequest)
		return
	}
	perr := m.be.setPassword(r.Context(), user, req.Password)
	outcome := "ok"
	if perr != nil {
		outcome = "failed"
	}
	// detail 绝不含口令。
	m.deps.Audit(&uid, "ftp.account.password", "user="+user+" "+outcome, clientIP(r))
	if perr != nil {
		log.Printf("ftp: passwd %q failed: %v", user, perr)
		http.Error(w, "ftp password change failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleToggle(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	user := chi.URLParamFromCtx(r.Context(), "user")
	if !validUser(user) {
		http.Error(w, errInvalidUser.Error(), http.StatusBadRequest)
		return
	}
	enable := chi.URLParamFromCtx(r.Context(), "verb") == "enable"
	terr := m.be.setEnabled(r.Context(), user, enable)
	outcome := "ok"
	if terr != nil {
		outcome = "failed"
	}
	verb := "disable"
	if enable {
		verb = "enable"
	}
	m.deps.Audit(&uid, "ftp.account."+verb, "user="+user+" "+outcome, clientIP(r))
	if terr != nil {
		log.Printf("ftp: %s %q failed: %v", verb, user, terr)
		http.Error(w, "ftp account toggle failed", http.StatusBadGateway)
		return
	}
	if err := m.ss.setEnabled(user, enable); err != nil {
		log.Printf("ftp: persist enabled meta failed: %v", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Settings handlers ---

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if !m.requireAdmin(w, r) {
		return
	}
	eff, err := m.ss.effective()
	if err != nil {
		log.Printf("ftp: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff})
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var in Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// HomeBase 非空则必须是绝对路径(作为家目录 chroot 根,空值落库后由默认兜底)。
	if in.HomeBase != "" && !isAbs(in.HomeBase) {
		http.Error(w, "home_base must be an absolute path", http.StatusBadRequest)
		return
	}
	if in.ConfigDir != "" && !isAbs(in.ConfigDir) {
		http.Error(w, "config_dir must be an absolute path", http.StatusBadRequest)
		return
	}
	if err := m.ss.save(in); err != nil {
		log.Printf("ftp: settings save failed: %v", err)
		http.Error(w, "settings save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "ftp.settings.update", "", clientIP(r))
	eff, err := m.ss.effective()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff})
}

func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return false
	}
	return true
}

// confirmed 检查危险操作的二次确认标记(与其它模块语义一致)。
func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP 从 RemoteAddr 取 IP(与 server 层一致,无代理信任)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func orEmpty(s []acctMeta) []acctMeta {
	if s == nil {
		return []acctMeta{}
	}
	return s
}

// isAbs 报告 p 是否绝对路径(避免直接 import path/filepath 仅用一处)。
func isAbs(p string) bool { return len(p) > 0 && p[0] == '/' }
