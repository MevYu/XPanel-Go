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
