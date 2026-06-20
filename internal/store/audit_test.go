package store

import (
	"database/sql"
	"testing"
)

func TestWriteAudit(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()

	u, _ := s.CreateUser("admin", "h", "admin")
	if err := s.WriteAudit(&u.ID, "login.success", "", "1.2.3.4"); err != nil {
		t.Fatalf("WriteAudit with userID: %v", err)
	}
	if err := s.WriteAudit(nil, "login.failure", "admin", "5.6.7.8"); err != nil {
		t.Fatalf("WriteAudit nil userID: %v", err)
	}

	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	if n != 2 {
		t.Fatalf("want 2 rows, got %d", n)
	}

	var (
		userID   sql.NullInt64
		action   string
		detail   string
		sourceIP string
	)
	err := s.DB.QueryRow(
		`SELECT user_id, action, detail, source_ip FROM audit_log WHERE action = ?`,
		"login.success",
	).Scan(&userID, &action, &detail, &sourceIP)
	if err != nil {
		t.Fatalf("query success row: %v", err)
	}
	if !userID.Valid || userID.Int64 != u.ID {
		t.Errorf("want user_id %d, got %+v", u.ID, userID)
	}
	if sourceIP != "1.2.3.4" {
		t.Errorf("want source_ip 1.2.3.4, got %q", sourceIP)
	}

	err = s.DB.QueryRow(
		`SELECT user_id, detail FROM audit_log WHERE action = ?`,
		"login.failure",
	).Scan(&userID, &detail)
	if err != nil {
		t.Fatalf("query failure row: %v", err)
	}
	if userID.Valid {
		t.Errorf("want NULL user_id for failure, got %+v", userID)
	}
	if detail != "admin" {
		t.Errorf("want detail admin, got %q", detail)
	}
}

func TestListAudit(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()

	u, _ := s.CreateUser("admin", "h", "admin")
	// 直接插入显式 ts,保证排序确定(同秒 WriteAudit 无法区分)。
	rows := []struct {
		ts     int64
		action string
		detail string
		ip     string
	}{
		{100, "login.success", "ok", "1.1.1.1"},
		{200, "panel.settings.update", "addr", "2.2.2.2"},
		{300, "login.failure", "bad", "3.3.3.3"},
	}
	for _, r := range rows {
		if _, err := s.DB.Exec(
			`INSERT INTO audit_log (ts, user_id, action, detail, source_ip) VALUES (?, ?, ?, ?, ?)`,
			r.ts, u.ID, r.action, r.detail, r.ip,
		); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	got, total, err := s.ListAudit(50, 0, "")
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	// 最新优先:ts 降序。
	if got[0].TS != 300 || got[1].TS != 200 || got[2].TS != 100 {
		t.Fatalf("not newest-first: %d %d %d", got[0].TS, got[1].TS, got[2].TS)
	}
	if got[0].Action != "login.failure" || got[0].Detail != "bad" || got[0].SourceIP != "3.3.3.3" {
		t.Fatalf("row[0] mismatch: %+v", got[0])
	}
	if got[0].UserID == nil || *got[0].UserID != u.ID {
		t.Fatalf("row[0] user_id mismatch: %+v", got[0].UserID)
	}

	// action 前缀过滤。
	got, total, err = s.ListAudit(50, 0, "login.")
	if err != nil {
		t.Fatalf("ListAudit filter: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("filtered total/len = %d/%d, want 2/2", total, len(got))
	}
	for _, e := range got {
		if e.Action[:6] != "login." {
			t.Fatalf("filter leaked: %q", e.Action)
		}
	}

	// limit/offset 分页:total 仍为过滤后全量。
	got, total, err = s.ListAudit(1, 1, "")
	if err != nil {
		t.Fatalf("ListAudit paged: %v", err)
	}
	if total != 3 {
		t.Fatalf("paged total = %d, want 3", total)
	}
	if len(got) != 1 || got[0].TS != 200 {
		t.Fatalf("paged window wrong: len=%d %+v", len(got), got)
	}

	// limit 钳制:>200 -> 200,<1 -> 1;offset<0 -> 0(不报错)。
	if _, _, err := s.ListAudit(99999, -5, ""); err != nil {
		t.Fatalf("clamp limit/offset: %v", err)
	}
	if _, _, err := s.ListAudit(0, 0, ""); err != nil {
		t.Fatalf("clamp zero limit: %v", err)
	}
}
