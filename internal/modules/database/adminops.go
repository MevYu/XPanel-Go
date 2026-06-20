package database

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/MevYu/XPanel-Go/internal/module"
)

// 管理类高危操作:重置超级用户口令、表维护、库字符集转换。全部 admin-only;
// 改超级用户口令与字符集转换额外要求 X-Confirm-Danger。标识符全经白名单+引用,口令经绑定参数。

const adminOpTimeout = 30 * time.Second

// maxRootPassword 限超级用户口令长度上限(与 ALTER USER/ROLE 绑定参数配合)。
const maxRootPassword = 128

// adminRoutes 注册管理类操作路由(mysql + postgres;convert-charset 仅 mysql)。
func (m *Module) adminRoutes(r module.Router) {
	r.Post("/mysql/root-password", m.handleRootPassword(dialectMySQL)) // 危险
	r.Post("/postgres/root-password", m.handleRootPassword(dialectPG)) // 危险
	r.Post("/mysql/maintain", m.handleMaintain(dialectMySQL))
	r.Post("/postgres/maintain", m.handleMaintain(dialectPG))
	r.Post("/mysql/convert-charset", m.handleConvertCharset) // 危险,仅 MySQL
}

// rootPasswordRequest 是重置超级用户口令的请求体。
type rootPasswordRequest struct {
	Password string `json:"password"`
}

// handleRootPassword 重置 DB 超级用户口令(mysql: root;postgres: 配置的超级用户)。
// 改成后必须把新口令写回设置(否则面板自身连不上库);先用新口令验证连接成功再持久化。
func (m *Module) handleRootPassword(d dialect) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, ok := m.requireAdmin(w, r)
		if !ok {
			return
		}
		if !confirmed(r) {
			http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
			return
		}
		var req rootPasswordRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.Password == "" || len(req.Password) > maxRootPassword {
			http.Error(w, "password must be 1..128 chars", http.StatusBadRequest)
			return
		}

		eff, ok := m.effectiveOr500(w)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), adminOpTimeout)
		defer cancel()
		connect := m.pgConn
		if d == dialectMySQL {
			connect = m.mysqlConn
		}
		be, err := connect(ctx, eff)
		if err != nil {
			log.Printf("database: connect (%s) failed: %v", m.engineName(d), err)
			http.Error(w, "database connection failed", http.StatusBadGateway)
			return
		}
		defer be.close()

		ops := sqlOps{be: be, d: d}
		err = ops.setSuperuserPassword(ctx, eff, req.Password)
		outcome := "ok"
		if err != nil {
			outcome = "failed"
		}
		m.deps.Audit(&uid, m.engineName(d)+".root_password", outcome, m.clientIP(r))
		if err != nil {
			log.Printf("database: %s root password failed: %v", m.engineName(d), err)
			http.Error(w, "database operation failed", http.StatusBadGateway)
			return
		}

		// 验证新口令可连接后再持久化;验证失败不动已存设置(避免把面板锁在外面)。
		if err := m.verifyAndPersistSuperuserPassword(ctx, d, eff, req.Password); err != nil {
			log.Printf("database: %s verify/persist new root password failed: %v", m.engineName(d), err)
			http.Error(w, "password changed but verification failed; settings not updated", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// setSuperuserPassword 改超级用户口令。口令经绑定参数,绝不进 SQL 文本。
// mysql: root@localhost 必改;127.0.0.1 / % 若存在也改(不存在的额外 host 忽略错误)。
// postgres: ALTER ROLE <超级用户> WITH PASSWORD ?(角色名经 validIdent + 引用)。
func (o sqlOps) setSuperuserPassword(ctx context.Context, eff Settings, password string) error {
	if o.d == dialectPG {
		role := eff.PGUser
		qr, err := o.d.quote(role)
		if err != nil {
			return err
		}
		return o.be.exec(ctx, "ALTER ROLE "+qr+" WITH PASSWORD ?", password)
	}
	// 主账户:root@localhost,必须成功。
	if err := o.be.exec(ctx, "ALTER USER 'root'@'localhost' IDENTIFIED BY ?", password); err != nil {
		return err
	}
	// 额外 host:存在则改,不存在的报错忽略(尽力而为)。
	for _, host := range []string{"127.0.0.1", "%"} {
		_ = o.be.exec(ctx, "ALTER USER 'root'@'"+host+"' IDENTIFIED BY ?", password)
	}
	return nil
}

// verifyAndPersistSuperuserPassword 用新口令开一条全新连接验证,成功后把新口令写回设置。
func (m *Module) verifyAndPersistSuperuserPassword(ctx context.Context, d dialect, eff Settings, password string) error {
	probe := eff
	connect := m.pgConn
	if d == dialectMySQL {
		probe.MySQLPassword = password
		connect = m.mysqlConn
	} else {
		probe.PGPassword = password
	}
	be, err := connect(ctx, probe)
	if err != nil {
		return err
	}
	if err := be.ping(ctx); err != nil {
		be.close()
		return err
	}
	be.close()
	// save 用整份 Settings 覆盖;eff 含解密后的全部口令,这里只替换目标口令后保存,其余原样。
	return m.ss.save(probe)
}

// maintainRequest 是表维护的请求体。
type maintainRequest struct {
	Database string `json:"database"`
	Action   string `json:"action"` // repair | optimize | analyze
	Table    string `json:"table"`  // 可选:单表;空则全库 base table
}

// maintainResult 是单表维护结果。
type maintainResult struct {
	Table   string `json:"table"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// validMaintainAction 报告 action 是否受支持。
func validMaintainAction(a string) bool {
	return a == "repair" || a == "optimize" || a == "analyze"
}

// handleMaintain 运行表维护(repair/optimize/analyze)。指定 table 则单表,否则全库 base table。
func (m *Module) handleMaintain(d dialect) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, ok := m.requireAdmin(w, r)
		if !ok {
			return
		}
		var req maintainRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if !validIdent(req.Database) {
			http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
			return
		}
		if !validMaintainAction(req.Action) {
			http.Error(w, "action must be repair|optimize|analyze", http.StatusBadRequest)
			return
		}
		if req.Table != "" && !validIdent(req.Table) {
			http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
			return
		}

		eff, ok := m.effectiveOr500(w)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), adminOpTimeout)
		defer cancel()
		be, err := m.connectDB(ctx, d, eff, req.Database)
		if err != nil {
			log.Printf("database: connect (%s) failed: %v", m.engineName(d), err)
			http.Error(w, "database connection failed", http.StatusBadGateway)
			return
		}
		defer be.close()

		ops := sqlOps{be: be, d: d}
		tables := []string{req.Table}
		if req.Table == "" {
			tables, err = ops.baseTables(ctx, req.Database)
			if err != nil {
				log.Printf("database: %s list base tables failed: %v", m.engineName(d), err)
				http.Error(w, "database operation failed", http.StatusBadGateway)
				return
			}
		}

		results := make([]maintainResult, 0, len(tables))
		for _, t := range tables {
			res := maintainResult{Table: t, OK: true, Message: "OK"}
			if err := ops.maintainTable(ctx, req.Database, t, req.Action); err != nil {
				res.OK = false
				res.Message = err.Error()
			}
			results = append(results, res)
		}
		m.deps.Audit(&uid, m.engineName(d)+".maintain", "db="+req.Database+" action="+req.Action, m.clientIP(r))
		writeJSON(w, http.StatusOK, map[string]any{"results": results})
	}
}

// baseTables 列出某库的全部 base table(MySQL: information_schema;PG: public schema)。库名作绑定参数。
func (o sqlOps) baseTables(ctx context.Context, db string) ([]string, error) {
	if o.d == dialectPG {
		return o.be.queryStrings(ctx,
			`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`)
	}
	return o.be.queryStrings(ctx,
		`SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME`,
		db)
}

// maintainTable 对单表执行一次维护。表名经白名单+引用进入 SQL。
func (o sqlOps) maintainTable(ctx context.Context, db, table, action string) error {
	if o.d == dialectPG {
		qt, err := qualifiedTable(dialectPG, db, table)
		if err != nil {
			return err
		}
		switch action {
		case "repair":
			return o.be.exec(ctx, "REINDEX TABLE "+qt)
		case "optimize":
			return o.be.exec(ctx, "VACUUM "+qt)
		case "analyze":
			return o.be.exec(ctx, "ANALYZE "+qt)
		}
		return errors.New("unknown action")
	}
	qt, err := qualifiedTable(dialectMySQL, db, table)
	if err != nil {
		return err
	}
	switch action {
	case "repair":
		return o.be.exec(ctx, "REPAIR TABLE "+qt)
	case "optimize":
		return o.be.exec(ctx, "OPTIMIZE TABLE "+qt)
	case "analyze":
		return o.be.exec(ctx, "ANALYZE TABLE "+qt)
	}
	return errors.New("unknown action")
}

// convertCharsetRequest 是库字符集/排序规则转换的请求体(仅 MySQL)。
type convertCharsetRequest struct {
	Database  string `json:"database"`
	Charset   string `json:"charset"`
	Collation string `json:"collation"`
}

// convertResult 是单条转换结果(ALTER DATABASE 作为一条 table="" 的条目)。
type convertResult struct {
	Table   string `json:"table"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// handleConvertCharset 转换某库及其全部 base table 的字符集/排序规则(仅 MySQL,危险)。
func (m *Module) handleConvertCharset(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	var req convertCharsetRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validIdent(req.Database) {
		http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
		return
	}
	if !validCharset(req.Charset) || !validCharset(req.Collation) {
		http.Error(w, errInvalidCharset.Error(), http.StatusBadRequest)
		return
	}

	eff, ok := m.effectiveOr500(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), adminOpTimeout)
	defer cancel()
	be, err := m.connectDB(ctx, dialectMySQL, eff, req.Database)
	if err != nil {
		log.Printf("database: connect (mysql) failed: %v", err)
		http.Error(w, "database connection failed", http.StatusBadGateway)
		return
	}
	defer be.close()

	ops := sqlOps{be: be, d: dialectMySQL}
	results := make([]convertResult, 0)

	qd, err := quoteMySQL(req.Database)
	if err != nil {
		http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
		return
	}
	// charset/collation 已 validCharset,非引号语境直接拼。
	dbStmt := "ALTER DATABASE " + qd + " CHARACTER SET " + req.Charset + " COLLATE " + req.Collation
	dbRes := convertResult{Table: "", OK: true, Message: "OK"}
	if err := be.exec(ctx, dbStmt); err != nil {
		dbRes.OK = false
		dbRes.Message = err.Error()
	}
	results = append(results, dbRes)

	tables, err := ops.baseTables(ctx, req.Database)
	if err != nil {
		log.Printf("database: mysql list base tables failed: %v", err)
		http.Error(w, "database operation failed", http.StatusBadGateway)
		return
	}
	for _, t := range tables {
		res := convertResult{Table: t, OK: true, Message: "OK"}
		qt, qerr := qualifiedTable(dialectMySQL, req.Database, t)
		if qerr != nil {
			res.OK = false
			res.Message = qerr.Error()
			results = append(results, res)
			continue
		}
		stmt := "ALTER TABLE " + qt + " CONVERT TO CHARACTER SET " + req.Charset + " COLLATE " + req.Collation
		if err := be.exec(ctx, stmt); err != nil {
			res.OK = false
			res.Message = err.Error()
		}
		results = append(results, res)
	}
	m.deps.Audit(&uid, "mysql.convert_charset", "db="+req.Database+" charset="+req.Charset, m.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
