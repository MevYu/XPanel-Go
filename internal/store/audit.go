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
