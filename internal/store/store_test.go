package store

import "testing"

func TestOpenRunsMigrations(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// 迁移应已建出三张表
	for _, table := range []string{"users", "refresh_tokens", "audit_log"} {
		var name string
		err := s.DB.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing: %v", table, err)
		}
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := s.DB.Exec(
		`INSERT INTO users (username, pass_hash, created_at) VALUES ('alice', 'x', 0)`,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// user_id=999 不存在,FK 约束必须拒绝插入
	_, err = s.DB.Exec(
		`INSERT INTO refresh_tokens (id, user_id, expires_at) VALUES ('t1', 999, 0)`,
	)
	if err == nil {
		t.Fatal("expected foreign key constraint error, got nil")
	}
}
