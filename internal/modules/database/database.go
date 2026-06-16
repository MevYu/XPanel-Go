// Package database 实现数据库管理模块:MySQL/MariaDB + PostgreSQL(列库、建删库、
// 列用户、建删用户、授权回收、改密)与 Redis(INFO、dbsize、flushdb)。
// 连接配置/路径可配置并持久化(密码 AES-GCM 加密),标识符严格白名单,危险操作需二次确认。
package database

import (
	"context"
	"encoding/json"
	"errors"
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

// Module 是可开关的数据库管理模块。
type Module struct {
	ss   *settingsStore
	bs   *backupStore
	deps Deps

	mysqlConn dbConnector
	pgConn    dbConnector
	redisConn redisConnector
	dumper    dumpRestorer
}

// New 建表并返回模块。secret 用于派生连接密码的 AES-GCM 密钥。
// 建表/派生失败直接 panic:模块无法工作。
func New(secret string, st *store.Store, deps Deps) *Module {
	cryp, err := newCryptor(secret)
	if err != nil {
		panic("database: init cryptor: " + err.Error())
	}
	ss, err := newSettingsStore(st, cryp)
	if err != nil {
		panic("database: init store: " + err.Error())
	}
	bs, err := newBackupStore(st)
	if err != nil {
		panic("database: init backup store: " + err.Error())
	}
	return &Module{
		ss:        ss,
		bs:        bs,
		deps:      deps,
		mysqlConn: mysqlConnector,
		pgConn:    pgConnector,
		redisConn: realRedisConnector,
		dumper:    cmdDumpRestorer{},
	}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "database", Name: "数据库", Category: "数据库"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "数据库", Icon: "database", Path: "/database"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:无外部命令依赖(用网络/socket 连库),始终可启用。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // 只读(admin):查看有效设置,密码屏蔽
	r.Put("/settings", m.handlePutSettings) // 写(admin):改设置

	// MySQL/MariaDB
	r.Get("/mysql/databases", m.handler(dialectMySQL, opListDB))
	r.Post("/mysql/databases", m.handler(dialectMySQL, opCreateDB))
	r.Delete("/mysql/databases", m.handler(dialectMySQL, opDropDB)) // 危险
	r.Get("/mysql/users", m.handler(dialectMySQL, opListUser))
	r.Post("/mysql/users", m.handler(dialectMySQL, opCreateUser))
	r.Delete("/mysql/users", m.handler(dialectMySQL, opDropUser)) // 危险
	r.Post("/mysql/users/password", m.handler(dialectMySQL, opPassword))
	r.Post("/mysql/grant", m.handler(dialectMySQL, opGrant))
	r.Post("/mysql/revoke", m.handler(dialectMySQL, opRevoke))

	// PostgreSQL
	r.Get("/postgres/databases", m.handler(dialectPG, opListDB))
	r.Post("/postgres/databases", m.handler(dialectPG, opCreateDB))
	r.Delete("/postgres/databases", m.handler(dialectPG, opDropDB)) // 危险
	r.Get("/postgres/users", m.handler(dialectPG, opListUser))
	r.Post("/postgres/users", m.handler(dialectPG, opCreateUser))
	r.Delete("/postgres/users", m.handler(dialectPG, opDropUser)) // 危险
	r.Post("/postgres/users/password", m.handler(dialectPG, opPassword))
	r.Post("/postgres/grant", m.handler(dialectPG, opGrant))
	r.Post("/postgres/revoke", m.handler(dialectPG, opRevoke))

	// 库级备份/恢复(在 DB 管理处直接操作,跨 mysql/postgres)
	m.backupRoutes(r)

	// Redis
	r.Get("/redis/info", m.handleRedisInfo)
	r.Get("/redis/dbsize", m.handleRedisDBSize)
	r.Post("/redis/flushdb", m.handleRedisFlush) // 危险
}

// opKind 标识一个 SQL 操作类型,驱动统一的 handler 派发。
type opKind int

const (
	opListDB opKind = iota
	opCreateDB
	opDropDB
	opListUser
	opCreateUser
	opDropUser
	opPassword
	opGrant
	opRevoke
)

// danger 报告该操作是否危险(需 X-Confirm-Danger + admin)。
func (k opKind) danger() bool { return k == opDropDB || k == opDropUser }

// write 报告该操作是否为写(需 admin)。只读 list 仍要 admin(连库凭据敏感),统一 admin。
func (k opKind) write() bool { return k != opListDB && k != opListUser }

func (k opKind) action() string {
	switch k {
	case opListDB:
		return "list_db"
	case opCreateDB:
		return "create_db"
	case opDropDB:
		return "drop_db"
	case opListUser:
		return "list_user"
	case opCreateUser:
		return "create_user"
	case opDropUser:
		return "drop_user"
	case opPassword:
		return "set_password"
	case opGrant:
		return "grant"
	case opRevoke:
		return "revoke"
	}
	return "unknown"
}

// opRequest 是建/删/授权类操作的请求体。
type opRequest struct {
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// handler 生成某方言某操作的 HTTP 处理器:统一 RBAC、危险确认、校验、连库、审计。
func (m *Module) handler(d dialect, k opKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, role := m.deps.Principal(r)
		if role != "admin" {
			http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
			return
		}
		if k.danger() && !confirmed(r) {
			http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
			return
		}

		var req opRequest
		if k != opListDB && k != opListUser {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
				return
			}
		}
		if !validateOp(w, k, req) {
			return
		}

		eff, err := m.ss.effective()
		if err != nil {
			log.Printf("database: settings load failed: %v", err)
			http.Error(w, "settings unavailable", http.StatusInternalServerError)
			return
		}
		connect := m.pgConn
		if d == dialectMySQL {
			connect = m.mysqlConn
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		be, err := connect(ctx, eff)
		if err != nil {
			log.Printf("database: connect (%s) failed: %v", m.engineName(d), err)
			http.Error(w, "database connection failed", http.StatusBadGateway)
			return
		}
		defer be.close()

		ops := sqlOps{be: be, d: d}
		result, err := runOp(ctx, ops, k, req)
		outcome := "ok"
		if err != nil {
			outcome = "failed"
		}
		if k.write() {
			m.deps.Audit(&uid, m.engineName(d)+"."+k.action(), opDetail(k, req)+" "+outcome, m.clientIP(r))
		}
		if err != nil {
			log.Printf("database: %s %s failed: %v", m.engineName(d), k.action(), err)
			http.Error(w, "database operation failed", http.StatusBadGateway)
			return
		}
		if result != nil {
			writeJSON(w, http.StatusOK, result)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (m *Module) engineName(d dialect) string {
	if d == dialectPG {
		return "postgres"
	}
	return "mysql"
}

// runOp 执行单个操作,list 类返回切片,其余返回 nil。
func runOp(ctx context.Context, ops sqlOps, k opKind, req opRequest) (any, error) {
	switch k {
	case opListDB:
		names, err := ops.listDatabases(ctx)
		return orEmpty(names), err
	case opListUser:
		names, err := ops.listUsers(ctx)
		return orEmpty(names), err
	case opCreateDB:
		return nil, ops.createDatabase(ctx, req.Database)
	case opDropDB:
		return nil, ops.dropDatabase(ctx, req.Database)
	case opCreateUser:
		return nil, ops.createUser(ctx, req.User, req.Password)
	case opDropUser:
		return nil, ops.dropUser(ctx, req.User)
	case opPassword:
		return nil, ops.setPassword(ctx, req.User, req.Password)
	case opGrant:
		return nil, ops.grantAll(ctx, req.Database, req.User)
	case opRevoke:
		return nil, ops.revokeAll(ctx, req.Database, req.User)
	}
	return nil, errors.New("unknown operation")
}

// validateOp 按操作所需字段做白名单校验。失败时已写 400,返回 false。
// 口令不进 SQL 标识符位置,只做非空/长度上限校验(不进审计 detail、不进日志)。
func validateOp(w http.ResponseWriter, k opKind, req opRequest) bool {
	needDB := k == opCreateDB || k == opDropDB || k == opGrant || k == opRevoke
	needUser := k == opCreateUser || k == opDropUser || k == opPassword || k == opGrant || k == opRevoke
	needPass := k == opCreateUser || k == opPassword
	if needDB && !validIdent(req.Database) {
		http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
		return false
	}
	if needUser && !validIdent(req.User) {
		http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
		return false
	}
	if needPass {
		if req.Password == "" || len(req.Password) > 256 {
			http.Error(w, "password must be 1..256 chars", http.StatusBadRequest)
			return false
		}
	}
	return true
}

// opDetail 为审计构造非敏感描述(绝不含口令)。
func opDetail(k opKind, req opRequest) string {
	switch k {
	case opCreateDB, opDropDB:
		return "db=" + req.Database
	case opCreateUser, opDropUser, opPassword:
		return "user=" + req.User
	case opGrant, opRevoke:
		return "db=" + req.Database + " user=" + req.User
	}
	return ""
}

// --- Redis handlers ---

func (m *Module) redisOpen(r *http.Request) (redisBackend, context.Context, context.CancelFunc, error) {
	eff, err := m.ss.effective()
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	be, err := m.redisConn(ctx, eff)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	return be, ctx, cancel, nil
}

func (m *Module) handleRedisInfo(w http.ResponseWriter, r *http.Request) {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	be, ctx, cancel, err := m.redisOpen(r)
	if err != nil {
		log.Printf("database: redis connect failed: %v", err)
		http.Error(w, "redis connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	info, err := be.info(ctx)
	if err != nil {
		log.Printf("database: redis info failed: %v", err)
		http.Error(w, "redis operation failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(info))
}

func (m *Module) handleRedisDBSize(w http.ResponseWriter, r *http.Request) {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	be, ctx, cancel, err := m.redisOpen(r)
	if err != nil {
		log.Printf("database: redis connect failed: %v", err)
		http.Error(w, "redis connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	n, err := be.dbSize(ctx)
	if err != nil {
		log.Printf("database: redis dbsize failed: %v", err)
		http.Error(w, "redis operation failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"dbsize": n})
}

// handleRedisFlush 清空当前库:危险操作,需 admin + X-Confirm-Danger + 审计。
func (m *Module) handleRedisFlush(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	be, ctx, cancel, err := m.redisOpen(r)
	if err != nil {
		log.Printf("database: redis connect failed: %v", err)
		http.Error(w, "redis connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	err = be.flushDB(ctx)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "redis.flushdb", outcome, m.clientIP(r))
	if err != nil {
		log.Printf("database: redis flushdb failed: %v", err)
		http.Error(w, "redis operation failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Settings handlers ---

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	eff, passSet, err := m.ss.masked()
	if err != nil {
		log.Printf("database: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff, "passwords_set": orEmptyStr(passSet)})
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var in Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := m.ss.save(in); err != nil {
		log.Printf("database: settings save failed: %v", err)
		http.Error(w, "settings save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "database.settings.update", "", m.clientIP(r))
	eff, passSet, err := m.ss.masked()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff, "passwords_set": orEmptyStr(passSet)})
}

// confirmed 检查危险操作的二次确认标记(与 firewall 模块语义一致)。
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

func orEmptyStr(s []string) []string { return orEmpty(s) }
