package php

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

	r.Get("/cli", m.handleCLIVersion) // 只读:命令行默认 php 版本

	r.Get("/ini/schema", m.handleIniSchema)          // 只读:表单化字段元数据(版本无关)
	r.Get("/versions/{version}/ini", m.handleGetIni) // 只读:php.ini 常用项(白名单)
	r.Put("/versions/{version}/ini", m.handlePutIni) // 危险:admin + X-Confirm-Danger,编辑 php.ini

	r.Get("/versions/{version}/ini/raw", m.handleGetRawIni) // 只读:原始 php.ini 全文
	r.Put("/versions/{version}/ini/raw", m.handlePutRawIni) // 危险:admin + X-Confirm-Danger,原始编辑

	r.Get("/disabled-functions/candidates", m.handleDangerFuncCandidates) // 只读:可管理危险函数候选
	r.Get("/versions/{version}/disabled-functions", m.handleGetDisabled)  // 只读:当前 disable_functions
	r.Put("/versions/{version}/disabled-functions", m.handlePutDisabled)  // 危险:admin + X-Confirm-Danger

	r.Get("/fpm/schema", m.handleFpmSchema)                         // 只读:fpm 字段元数据(版本无关)
	r.Get("/versions/{version}/fpm/config", m.handleGetFpm)         // 只读:fpm pool 参数
	r.Put("/versions/{version}/fpm/config", m.handlePutFpm)         // 危险:admin + X-Confirm-Danger
	r.Get("/versions/{version}/fpm/status", m.handleFpmStatus)      // 只读:systemctl status
	r.Get("/versions/{version}/log/{kind:slow|error}", m.handleLog) // 只读:慢日志/错误日志 tail

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
	Version    string `json:"version"`
	Banner     string `json:"banner"`      // php -v 首行;detect 失败为空
	FpmUnit    string `json:"fpm_unit"`    // 对应 php-fpm systemd 单元名
	FpmActive  bool   `json:"fpm_active"`  // php-fpm 是否在运行(systemctl is-active)
	CLIDefault bool   `json:"cli_default"` // 是否为命令行默认版本(php -v 横幅匹配)
}

func (m *Module) handleListVersions(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	cliBanner, _ := m.run.CLIVersion()
	cliBanner = firstLine(cliBanner)
	versions := detectVersions(set.InstallBase)
	out := make([]VersionInfo, 0, len(versions))
	for _, v := range versions {
		info := VersionInfo{Version: v, FpmUnit: set.fpmUnit(v)}
		if banner, err := m.run.Version(set.phpBin(v)); err == nil {
			info.Banner = firstLine(banner)
			info.CLIDefault = cliBanner != "" && info.Banner == cliBanner
		}
		info.FpmActive = m.run.FpmActive(info.FpmUnit)
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) handleCLIVersion(w http.ResponseWriter, _ *http.Request) {
	banner, err := m.run.CLIVersion()
	resp := struct {
		Available bool   `json:"available"`
		Banner    string `json:"banner"`
	}{Available: err == nil, Banner: firstLine(banner)}
	writeJSON(w, http.StatusOK, resp)
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

func (m *Module) handleIniSchema(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, iniSchema)
}

// --- raw php.ini ---

func (m *Module) handleGetRawIni(w http.ResponseWriter, r *http.Request) {
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
		log.Printf("php: read raw ini for %q failed: %v", version, err)
		http.Error(w, "php.ini unavailable", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(content)
}

func (m *Module) handlePutRawIni(w http.ResponseWriter, r *http.Request) {
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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRawIni+1))
	if err != nil {
		http.Error(w, "ini body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := validateRawIni(string(body)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	path := set.iniPath(version)
	if _, err := os.Stat(path); err != nil {
		http.Error(w, "php.ini unavailable", http.StatusNotFound)
		return
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		serverError(w, "write raw ini", err)
		return
	}
	m.deps.Audit(&uid, "php.ini.raw_update", version, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// --- disable_functions ---

func (m *Module) handleDangerFuncCandidates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, DangerousFuncList())
}

func (m *Module) handleGetDisabled(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, parseDisableFunctions(string(content)))
}

func (m *Module) handlePutDisabled(w http.ResponseWriter, r *http.Request) {
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
	var funcs []string
	if !decode(w, r, &funcs) {
		return
	}
	if err := validateDisableFunctions(funcs); err != nil {
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
	updated := applyDisableFunctions(string(content), funcs)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		serverError(w, "write ini", err)
		return
	}
	m.deps.Audit(&uid, "php.disable_functions.update", version+" "+strings.Join(funcs, ","), m.clientIP(r))
	writeJSON(w, http.StatusOK, parseDisableFunctions(updated))
}

// --- fpm pool config ---

func (m *Module) handleFpmSchema(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, fpmSchema)
}

func (m *Module) handleGetFpm(w http.ResponseWriter, r *http.Request) {
	version, ok := versionParam(w, r)
	if !ok {
		return
	}
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	content, err := os.ReadFile(set.fpmPoolConf(version))
	if err != nil {
		log.Printf("php: read fpm pool for %q failed: %v", version, err)
		http.Error(w, "fpm pool config unavailable", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, parseFpmConfig(string(content)))
}

func (m *Module) handlePutFpm(w http.ResponseWriter, r *http.Request) {
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
	if err := validateFpmChanges(changes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	path := set.fpmPoolConf(version)
	content, err := os.ReadFile(path)
	if err != nil {
		log.Printf("php: read fpm pool for %q failed: %v", version, err)
		http.Error(w, "fpm pool config unavailable", http.StatusNotFound)
		return
	}
	updated := applyFpmChanges(string(content), changes)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		serverError(w, "write fpm pool", err)
		return
	}
	m.deps.Audit(&uid, "php.fpm.config", version+" "+strings.Join(keys(changes), ","), m.clientIP(r))
	writeJSON(w, http.StatusOK, parseFpmConfig(updated))
}

func (m *Module) handleFpmStatus(w http.ResponseWriter, r *http.Request) {
	version, ok := versionParam(w, r)
	if !ok {
		return
	}
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	unit := set.fpmUnit(version)
	out, _ := m.run.FpmAction("status", unit)
	resp := struct {
		Unit   string `json:"unit"`
		Active bool   `json:"active"`
		Status string `json:"status"`
	}{Unit: unit, Active: m.run.FpmActive(unit), Status: out}
	writeJSON(w, http.StatusOK, resp)
}

// --- logs ---

func (m *Module) handleLog(w http.ResponseWriter, r *http.Request) {
	version, ok := versionParam(w, r)
	if !ok {
		return
	}
	set, err := m.ps.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	var path string
	switch chi.URLParamFromCtx(r.Context(), "kind") {
	case "slow":
		path = set.slowLogPath(version)
	case "error":
		path = set.errorLogPath(version)
	default:
		http.Error(w, "unknown log kind", http.StatusBadRequest)
		return
	}
	tail, ok := readLogTail(path, logTailLines(r))
	if !ok {
		http.Error(w, "log unavailable", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(tail))
}

// logTailLines 取 ?lines= 查询参数(1..2000),缺省/非法回退 200。
func logTailLines(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("lines"))
	if err != nil || n < 1 {
		return 200
	}
	if n > 2000 {
		return 2000
	}
	return n
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
