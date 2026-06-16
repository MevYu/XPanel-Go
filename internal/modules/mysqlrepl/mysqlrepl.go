// Package mysqlrepl 实现 MySQL 主从/读写分离管理(对标 aaPanel Pro 数据库主从):
// 在主库建复制用户、查 master status;从库 CHANGE MASTER TO + start slave;
// 查看复制状态、start/stop/reset slave。连接凭证 AES-GCM 加密落库,标识符严格白名单,
// 变更需 admin,危险操作(stop/reset)需 X-Confirm-Danger 二次确认并审计。
package mysqlrepl

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的 MySQL 主从管理模块。
type Module struct {
	ss   *settingsStore
	deps Deps

	connect connector // 抽成字段便于测试注入 mock
}

// New 建表并返回模块。secret 用于派生连接密码的 AES-GCM 密钥。
// 建表/派生失败直接 panic:模块无法工作。
func New(secret string, st *store.Store, deps Deps) *Module {
	cryp, err := newCryptor(secret)
	if err != nil {
		panic("mysqlrepl: init cryptor: " + err.Error())
	}
	ss, err := newSettingsStore(st, cryp)
	if err != nil {
		panic("mysqlrepl: init store: " + err.Error())
	}
	return &Module{ss: ss, deps: deps, connect: realConnector}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "mysqlrepl", Name: "MySQL主从", Category: "数据库"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "MySQL主从", Icon: "git-branch", Path: "/mysqlrepl"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:无外部命令依赖(用网络连库),始终可启用。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // 只读(admin):查看有效设置,密码屏蔽
	r.Put("/settings", m.handlePutSettings) // 写(admin):改设置

	r.Get("/master/status", m.handleMasterStatus) // 查主库 SHOW MASTER STATUS
	r.Post("/master/repl-user", m.handleReplUser) // 在主库建复制用户(变更)

	r.Get("/slave/status", m.handleSlaveStatus) // 查从库 SHOW SLAVE STATUS
	r.Post("/slave/configure", m.handleConfigureSlave)
	r.Post("/slave/start", m.handleStartSlave)
	r.Post("/slave/stop", m.handleStopSlave)   // 危险
	r.Post("/slave/reset", m.handleResetSlave) // 危险
}

// --- 连接辅助 ---

// openMaster / openSlave 用有效设置建到主/从库的连接。
func (m *Module) open(r *http.Request, cfg connConfig) (mysqlBackend, context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	be, err := m.connect(ctx, cfg)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	return be, ctx, cancel, nil
}

// requireAdmin 报告主体是否 admin,否则写 403。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// --- 状态查询 ---

func (m *Module) handleMasterStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	eff, err := m.effective(w)
	if err != nil {
		return
	}
	be, ctx, cancel, err := m.open(r, eff.masterConn())
	if err != nil {
		log.Printf("mysqlrepl: master connect failed: %v", err)
		http.Error(w, "master connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	st, err := masterStatus(ctx, be)
	if err != nil {
		log.Printf("mysqlrepl: master status failed: %v", err)
		http.Error(w, "master status failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (m *Module) handleSlaveStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	eff, err := m.effective(w)
	if err != nil {
		return
	}
	be, ctx, cancel, err := m.open(r, eff.slaveConn())
	if err != nil {
		log.Printf("mysqlrepl: slave connect failed: %v", err)
		http.Error(w, "slave connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	st, err := slaveStatus(ctx, be)
	if err != nil {
		log.Printf("mysqlrepl: slave status failed: %v", err)
		http.Error(w, "slave status failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// --- 变更操作 ---

func (m *Module) handleReplUser(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req configureMasterReq
	if !decode(w, r, &req) {
		return
	}
	if !validIdent(req.ReplUser) {
		http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
		return
	}
	if !validPassword(w, req.ReplPassword) {
		return
	}
	eff, err := m.effective(w)
	if err != nil {
		return
	}
	be, ctx, cancel, err := m.open(r, eff.masterConn())
	if err != nil {
		log.Printf("mysqlrepl: master connect failed: %v", err)
		http.Error(w, "master connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	err = createReplUser(ctx, be, req)
	m.audit(uid, "mysqlrepl.repl_user", "user="+req.ReplUser, r, err)
	if err != nil {
		log.Printf("mysqlrepl: create repl user failed: %v", err)
		http.Error(w, "create repl user failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleConfigureSlave(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req configureSlaveReq
	if !decode(w, r, &req) {
		return
	}
	if !validIdent(req.ReplUser) {
		http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
		return
	}
	if !validPassword(w, req.ReplPassword) {
		return
	}
	if req.MasterHost == "" || req.MasterPort <= 0 || req.MasterPort > 65535 {
		http.Error(w, "master_host required and master_port must be 1..65535", http.StatusBadRequest)
		return
	}
	eff, err := m.effective(w)
	if err != nil {
		return
	}
	be, ctx, cancel, err := m.open(r, eff.slaveConn())
	if err != nil {
		log.Printf("mysqlrepl: slave connect failed: %v", err)
		http.Error(w, "slave connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	err = configureSlave(ctx, be, req)
	m.audit(uid, "mysqlrepl.configure_slave", "master="+req.MasterHost, r, err)
	if err != nil {
		log.Printf("mysqlrepl: configure slave failed: %v", err)
		http.Error(w, "configure slave failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleStartSlave(w http.ResponseWriter, r *http.Request) {
	m.slaveControl(w, r, "mysqlrepl.start_slave", false, startSlave)
}

func (m *Module) handleStopSlave(w http.ResponseWriter, r *http.Request) {
	m.slaveControl(w, r, "mysqlrepl.stop_slave", true, stopSlave)
}

func (m *Module) handleResetSlave(w http.ResponseWriter, r *http.Request) {
	m.slaveControl(w, r, "mysqlrepl.reset_slave", true, resetSlave)
}

// slaveControl 统一 start/stop/reset:RBAC、危险确认、连库、执行、审计。
func (m *Module) slaveControl(w http.ResponseWriter, r *http.Request, action string, danger bool, op func(context.Context, mysqlBackend) error) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if danger && !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	eff, err := m.effective(w)
	if err != nil {
		return
	}
	be, ctx, cancel, err := m.open(r, eff.slaveConn())
	if err != nil {
		log.Printf("mysqlrepl: slave connect failed: %v", err)
		http.Error(w, "slave connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	err = op(ctx, be)
	m.audit(uid, action, "", r, err)
	if err != nil {
		log.Printf("mysqlrepl: %s failed: %v", action, err)
		http.Error(w, "slave control failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Settings handlers ---

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	eff, passSet, err := m.ss.masked()
	if err != nil {
		log.Printf("mysqlrepl: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff, "passwords_set": orEmpty(passSet)})
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var in Settings
	if !decode(w, r, &in) {
		return
	}
	if err := m.ss.save(in); err != nil {
		log.Printf("mysqlrepl: settings save failed: %v", err)
		http.Error(w, "settings save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "mysqlrepl.settings.update", "", m.clientIP(r))
	eff, passSet, err := m.ss.masked()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff, "passwords_set": orEmpty(passSet)})
}

// --- 小工具 ---

// effective 取有效设置,失败时已写 500 并返回 err。
func (m *Module) effective(w http.ResponseWriter) (Settings, error) {
	eff, err := m.ss.effective()
	if err != nil {
		log.Printf("mysqlrepl: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
	}
	return eff, err
}

// audit 写审计:成功 ok / 失败 failed 追加到 detail。
func (m *Module) audit(uid int64, action, detail string, r *http.Request, opErr error) {
	outcome := "ok"
	if opErr != nil {
		outcome = "failed"
	}
	if detail != "" {
		detail += " "
	}
	m.deps.Audit(&uid, action, detail+outcome, m.clientIP(r))
}

// validPassword 校验复制口令非空且长度合理(不进审计 detail、不进日志)。
func validPassword(w http.ResponseWriter, pw string) bool {
	if pw == "" || len(pw) > 256 {
		http.Error(w, "password must be 1..256 chars", http.StatusBadRequest)
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
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

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
