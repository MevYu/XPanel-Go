package store

import (
	"database/sql"
	"time"
)

// WriteAudit 写一条审计记录。userID 为 nil 表示主体未知(如失败登录)。
func (s *Store) WriteAudit(userID *int64, action, detail, sourceIP string) error {
	var uid sql.NullInt64
	if userID != nil {
		uid = sql.NullInt64{Int64: *userID, Valid: true}
	}
	_, err := s.DB.Exec(
		`INSERT INTO audit_log (ts, user_id, action, detail, source_ip) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), uid, action, detail, sourceIP,
	)
	return err
}

// AuditEntry 是审计日志的只读视图。UserID 为 nil 表示主体未知(如失败登录)。
type AuditEntry struct {
	TS       int64  `json:"ts"`
	UserID   *int64 `json:"user_id"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
	SourceIP string `json:"source_ip"`
}

// ListAudit 按 ts 降序(最新优先)返回审计记录及过滤后的总数。
// limit 钳制到 [1,200],offset 钳制到 >=0。action 非空时按前缀过滤(action LIKE action+'%')。
func (s *Store) ListAudit(limit, offset int, action string) ([]AuditEntry, int, error) {
	if limit < 1 {
		limit = 1
	} else if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	countSQL := `SELECT COUNT(*) FROM audit_log`
	listSQL := `SELECT ts, user_id, action, detail, source_ip FROM audit_log`
	var args []any
	if action != "" {
		countSQL += ` WHERE action LIKE ?`
		listSQL += ` WHERE action LIKE ?`
		args = append(args, action+"%")
	}
	listSQL += ` ORDER BY ts DESC LIMIT ? OFFSET ?`

	var total int
	if err := s.DB.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.DB.Query(listSQL, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	entries := []AuditEntry{}
	for rows.Next() {
		var (
			e   AuditEntry
			uid sql.NullInt64
			det sql.NullString
			ip  sql.NullString
		)
		if err := rows.Scan(&e.TS, &uid, &e.Action, &det, &ip); err != nil {
			return nil, 0, err
		}
		if uid.Valid {
			v := uid.Int64
			e.UserID = &v
		}
		e.Detail = det.String
		e.SourceIP = ip.String
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return entries, total, nil
}
