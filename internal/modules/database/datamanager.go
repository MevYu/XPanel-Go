package database

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 数据浏览器:列表、分页浏览、执行任意 SQL。全部 admin-only 并审计;任意 SQL 额外要求 X-Confirm-Danger。
// 标识符(库名/表名)只经 validIdent + 方言引用进入 SQL;LIMIT/OFFSET/库名过滤值用绑定参数。

const (
	rowsDefaultLimit = 50
	rowsMaxLimit     = 500
	queryMaxRows     = 1000    // 任意 SQL 返回行上限,超出标记 truncated
	queryMaxSQLLen   = 100_000 // SQL 文本长度上限
	dataMgrTimeout   = 30 * time.Second
)

// connectDB 按方言打开一个连到指定库的后端。dbName 必须已过 validIdent。
// MySQL 用默认连接(查询里按 `db`.`tbl` 限定);PG 必须 per-database 连接。
func (m *Module) connectDB(ctx context.Context, d dialect, eff Settings, dbName string) (sqlBackend, error) {
	if d == dialectPG {
		return m.pgConnDB(ctx, eff, dbName)
	}
	return m.mysqlConnDB(ctx, eff, dbName)
}

// requireAdmin 写 403 并返回 false(非 admin)。返回当前主体 uid 供审计。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// tableInfo 是一张表的元信息。
type tableInfo struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"` // 行数(MySQL 来自 information_schema 估计;PG 置 0)
}

// handleTables: GET /{engine}/tables?database=DB — 列某库的表。
func (m *Module) handleTables(d dialect) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, ok := m.requireAdmin(w, r)
		if !ok {
			return
		}
		db := r.URL.Query().Get("database")
		if !validIdent(db) {
			http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
			return
		}
		eff, ok := m.effectiveOr500(w)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), dataMgrTimeout)
		defer cancel()
		be, err := m.connectDB(ctx, d, eff, db)
		if err != nil {
			log.Printf("database: connect (%s) failed: %v", m.engineName(d), err)
			http.Error(w, "database connection failed", http.StatusBadGateway)
			return
		}
		defer be.close()

		tables, err := listTables(ctx, be, d, db)
		if err != nil {
			log.Printf("database: %s tables failed: %v", m.engineName(d), err)
			http.Error(w, "database operation failed", http.StatusBadGateway)
			return
		}
		m.deps.Audit(&uid, m.engineName(d)+".tables", "db="+db, m.clientIP(r))
		writeJSON(w, http.StatusOK, map[string]any{"tables": tables})
	}
}

// listTables 列表。MySQL 从 information_schema 取表名与行数估计(库名绑定参数);PG 列 public schema(行数置 0)。
func listTables(ctx context.Context, be sqlBackend, d dialect, db string) ([]tableInfo, error) {
	if d == dialectPG {
		names, err := be.queryStrings(ctx,
			`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name`)
		if err != nil {
			return nil, err
		}
		out := make([]tableInfo, 0, len(names))
		for _, n := range names {
			out = append(out, tableInfo{Name: n})
		}
		return out, nil
	}
	rows, err := be.queryRows(ctx,
		`SELECT TABLE_NAME AS name, IFNULL(TABLE_ROWS,0) AS rows FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME`,
		db)
	if err != nil {
		return nil, err
	}
	out := make([]tableInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, tableInfo{Name: r["name"], Rows: int64(atoiOr0(r["rows"]))})
	}
	return out, nil
}

// handleRows: GET /{engine}/rows?database=DB&table=T&limit=L&offset=O — 分页浏览某表。
func (m *Module) handleRows(d dialect) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, ok := m.requireAdmin(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		db, table := q.Get("database"), q.Get("table")
		if !validIdent(db) || !validIdent(table) {
			http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
			return
		}
		limit := clampLimit(q.Get("limit"))
		offset := parseOffset(q.Get("offset"))

		qualified, err := qualifiedTable(d, db, table)
		if err != nil {
			http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
			return
		}

		eff, ok := m.effectiveOr500(w)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), dataMgrTimeout)
		defer cancel()
		be, err := m.connectDB(ctx, d, eff, db)
		if err != nil {
			log.Printf("database: connect (%s) failed: %v", m.engineName(d), err)
			http.Error(w, "database connection failed", http.StatusBadGateway)
			return
		}
		defer be.close()

		cols, data, _, err := be.queryTable(ctx, 0, "SELECT * FROM "+qualified+" LIMIT ? OFFSET ?", limit, offset)
		if err != nil {
			log.Printf("database: %s rows failed: %v", m.engineName(d), err)
			http.Error(w, "database operation failed", http.StatusBadGateway)
			return
		}
		var total int64
		if tc, err := be.queryStrings(ctx, "SELECT COUNT(*) FROM "+qualified); err == nil && len(tc) == 1 {
			total = int64(atoiOr0(tc[0]))
		}
		m.deps.Audit(&uid, m.engineName(d)+".rows", "db="+db+" table="+table, m.clientIP(r))
		writeJSON(w, http.StatusOK, map[string]any{
			"columns": orEmpty(cols),
			"rows":    orEmptyRows(data),
			"total":   total,
		})
	}
}

// queryRequest 是任意 SQL 请求体。
type queryRequest struct {
	Database string `json:"database"`
	SQL      string `json:"sql"`
}

// handleQuery: POST /{engine}/query — 执行任意 SQL(危险:admin + X-Confirm-Danger)。
func (m *Module) handleQuery(d dialect) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, ok := m.requireAdmin(w, r)
		if !ok {
			return
		}
		if !confirmed(r) {
			http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
			return
		}
		var req queryRequest
		// 体上限 = SQL 上限 + 库名/JSON 框架余量。
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, queryMaxSQLLen+1024)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if !validIdent(req.Database) {
			http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
			return
		}
		sqlText := strings.TrimSpace(req.SQL)
		if sqlText == "" || len(sqlText) > queryMaxSQLLen {
			http.Error(w, "sql must be 1.."+strconv.Itoa(queryMaxSQLLen)+" chars", http.StatusBadRequest)
			return
		}

		eff, ok := m.effectiveOr500(w)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), dataMgrTimeout)
		defer cancel()
		be, err := m.connectDB(ctx, d, eff, req.Database)
		if err != nil {
			log.Printf("database: connect (%s) failed: %v", m.engineName(d), err)
			http.Error(w, "database connection failed", http.StatusBadGateway)
			return
		}
		defer be.close()

		m.deps.Audit(&uid, m.engineName(d)+".query", "engine="+m.engineName(d)+" db="+req.Database+" sql="+truncate(sqlText, 200), m.clientIP(r))

		cols, data, truncated, err := be.queryTable(ctx, queryMaxRows, sqlText)
		if err != nil {
			// admin 工具:数据库错误文本可安全回显(不含连接串/口令)。
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(cols) == 0 {
			// 无结果列:DDL/DML 已由 QueryContext 执行。RowsAffected 不可得 → 0。
			writeJSON(w, http.StatusOK, map[string]any{"affected": 0, "message": "OK"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"columns":   cols,
			"rows":      orEmptyRows(data),
			"truncated": truncated,
		})
	}
}

// effectiveOr500 取有效设置,失败时写 500 并返回 false。
func (m *Module) effectiveOr500(w http.ResponseWriter) (Settings, bool) {
	eff, err := m.ss.effective()
	if err != nil {
		log.Printf("database: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return Settings{}, false
	}
	return eff, true
}

// qualifiedTable 构造已引用、已校验的限定表名:MySQL `db`.`tbl`;PG "public"."tbl"。
func qualifiedTable(d dialect, db, table string) (string, error) {
	if d == dialectPG {
		qs, err := quotePG("public")
		if err != nil {
			return "", err
		}
		qt, err := quotePG(table)
		if err != nil {
			return "", err
		}
		return qs + "." + qt, nil
	}
	qd, err := quoteMySQL(db)
	if err != nil {
		return "", err
	}
	qt, err := quoteMySQL(table)
	if err != nil {
		return "", err
	}
	return qd + "." + qt, nil
}

// clampLimit 解析 limit,缺省/非法 → 50,否则夹到 [1,500]。
func clampLimit(s string) int {
	if s == "" {
		return rowsDefaultLimit
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return rowsDefaultLimit
	}
	if n < 1 {
		return 1
	}
	if n > rowsMaxLimit {
		return rowsMaxLimit
	}
	return n
}

// parseOffset 解析 offset,默认 0,负数归 0。
func parseOffset(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// truncate 截断到 n 字节(超出加省略号),用于审计 detail。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// orEmptyRows 把 nil 行集替换为空切片(JSON 输出 [] 而非 null)。
func orEmptyRows(rows [][]*string) [][]*string {
	if rows == nil {
		return [][]*string{}
	}
	return rows
}
