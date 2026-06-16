package php

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// errInstallUnavailable 表示当前环境未提供 PHP 安装后端。
var errInstallUnavailable = errors.New("php: install backend unavailable in this environment")

// Deps 注入宿主能力,避免反向依赖 server/store 包。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的 PHP 多版本管理模块。
type Module struct {
	ps   *phpStore
	run  PHPRunner
	inst Installer
	deps Deps
}

// New 建表并返回模块。建表失败(DB 不可用)直接 panic:模块无法工作。
// run/inst 为 nil 时用默认实现(系统二进制 / 不可用安装器)。
func New(st *store.Store, run PHPRunner, inst Installer, deps Deps) *Module {
	ps, err := newPHPStore(st)
	if err != nil {
		panic("php: init store: " + err.Error())
	}
	if run == nil {
		run = NewRunner()
	}
	if inst == nil {
		inst = NewUnavailableInstaller()
	}
	return &Module{ps: ps, run: run, inst: inst, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "php", Name: "PHP", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "PHP", Icon: "file-code", Path: "/php"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:无 systemctl(管理 php-fpm 必需)则不允许启用。
func (m *Module) HealthCheck() error { return m.run.Available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // 只读:任意已认证角色
	r.Put("/settings", m.handlePutSettings) // 写:admin

	r.Get("/versions", m.handleListVersions) // 只读:检测已安装版本
	r.Post("/install", m.handleInstall)      // 危险:admin + X-Confirm-Danger,安装新版本

	r.Get("/versions/{version}/ini", m.handleGetIni) // 只读:php.ini 常用项
	r.Put("/versions/{version}/ini", m.handlePutIni) // 危险:admin + X-Confirm-Danger,编辑 php.ini

	r.Get("/versions/{version}/extensions", m.handleListExtensions)                             // 只读
	r.Post("/versions/{version}/extensions/{ext}/{op:enable|disable}", m.handleToggleExtension) // 危险:admin + X-Confirm-Danger

	r.Post("/versions/{version}/fpm/{verb:start|stop|restart}", m.handleFpmAction) // 危险:admin + X-Confirm-Danger
}

// requireAdmin 校验 admin 角色。失败时已写 403,返回 ok=false。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// confirmed 检查危险操作的二次确认标记(与其它模块语义一致)。
func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

// versionParam 取并校验 URL 里的 {version}。非法时已写 400,返回 ok=false。
func versionParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := chi.URLParamFromCtx(r.Context(), "version")
	if !ValidVersion(v) {
		http.Error(w, "invalid version", http.StatusBadRequest)
		return "", false
	}
	return v, true
}

// --- Settings ---

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	s, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var s Settings
	if !decode(w, r, &s) {
		return
	}
	if err := s.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ps.setSettings(s); err != nil {
		serverError(w, "save settings", err)
		return
	}
	m.deps.Audit(&uid, "php.settings.update", s.InstallBase, m.clientIP(r))
	writeJSON(w, http.StatusOK, s)
}

// --- Versions ---

// VersionInfo 是一个已安装版本的视图。
type VersionInfo struct {
	Version string `json:"version"`
	Banner  string `json:"banner"` // php -v 首行;detect 失败为空
}

func (m *Module) handleListVersions(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	versions := detectVersions(set.InstallBase)
	out := make([]VersionInfo, 0, len(versions))
	for _, v := range versions {
		info := VersionInfo{Version: v}
		if banner, err := m.run.Version(set.phpBin(v)); err == nil {
			info.Banner = firstLine(banner)
		}
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) handleInstall(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	var body struct {
		Version string `json:"version"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !ValidVersion(body.Version) {
		http.Error(w, "invalid version", http.StatusBadRequest)
		return
	}
	out, err := m.inst.Install(body.Version)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "php.install", body.Version+" "+outcome, m.clientIP(r))
	if err != nil {
		// out 含命令原始输出(路径/内部状态),只留服务端,不回传客户端。
		log.Printf("php: install %q failed: %v; output: %s", body.Version, err, out)
		if errors.Is(err, errInstallUnavailable) {
			http.Error(w, "install backend unavailable", http.StatusNotImplemented)
			return
		}
		http.Error(w, "install failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// --- php.ini ---

func (m *Module) handleGetIni(w http.ResponseWriter, r *http.Request) {
	version, ok := versionParam(w, r)
	if !ok {
		return
	}
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	content, err := os.ReadFile(set.iniPath(version))
	if err != nil {
		log.Printf("php: read ini for %q failed: %v", version, err)
		http.Error(w, "php.ini unavailable", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, parseIni(string(content)))
}

func (m *Module) handlePutIni(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	version, ok := versionParam(w, r)
	if !ok {
		return
	}
	var changes map[string]string
	if !decode(w, r, &changes) {
		return
	}
	if err := validateIniChanges(changes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	path := set.iniPath(version)
	content, err := os.ReadFile(path)
	if err != nil {
		log.Printf("php: read ini for %q failed: %v", version, err)
		http.Error(w, "php.ini unavailable", http.StatusNotFound)
		return
	}
	updated := applyIniChanges(string(content), changes)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		serverError(w, "write ini", err)
		return
	}
	m.deps.Audit(&uid, "php.ini.update", version+" "+strings.Join(keys(changes), ","), m.clientIP(r))
	writeJSON(w, http.StatusOK, parseIni(updated))
}

// --- Extensions ---

func (m *Module) handleListExtensions(w http.ResponseWriter, r *http.Request) {
	version, ok := versionParam(w, r)
	if !ok {
		return
	}
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	raw, err := m.run.Modules(set.phpBin(version))
	if err != nil {
		log.Printf("php: list modules for %q failed: %v", version, err)
		http.Error(w, "extensions unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, parseModules(raw))
}

func (m *Module) handleToggleExtension(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	version, ok := versionParam(w, r)
	if !ok {
		return
	}
	ext := chi.URLParamFromCtx(r.Context(), "ext")
	if !ValidExtName(ext) {
		http.Error(w, "invalid extension name", http.StatusBadRequest)
		return
	}
	op := chi.URLParamFromCtx(r.Context(), "op")
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	if err := m.toggleExtension(set, version, ext, op == "enable"); err != nil {
		serverError(w, "toggle extension", err)
		return
	}
	m.deps.Audit(&uid, "php.ext."+op, version+" "+ext, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// toggleExtension 通过在版本的 php.d 目录写/删 <ext>.ini 启用/禁用扩展。
// version/ext 须已白名单校验,故拼出的路径无逃逸风险。
func (m *Module) toggleExtension(set Settings, version, ext string, enable bool) error {
	dir := set.extConfDir(version)
	path := filepath.Join(dir, ext+".ini")
	if enable {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("extension="+ext+"\n"), 0o644)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// --- php-fpm ---

func (m *Module) handleFpmAction(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	version, ok := versionParam(w, r)
	if !ok {
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	unit := set.fpmUnit(version)
	out, err := m.run.FpmAction(verb, unit)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "php.fpm."+verb, unit+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("php: fpm %s for %q failed: %v", verb, unit, err)
		http.Error(w, "fpm operation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// --- helpers ---

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func serverError(w http.ResponseWriter, what string, err error) {
	log.Printf("php: %s failed: %v", what, err)
	http.Error(w, what+" failed", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
