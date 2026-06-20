package database

import (
	"net/http"
	"strings"
	"testing"
)

// --- root-password ---

func TestRootPasswordMySQLAdmin(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	rec := do(router(m), "POST", "/mysql/root-password", `{"password":"NewR00t!"}`,
		map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("root-password = %d body=%s", rec.Code, rec.Body)
	}
	// localhost 必改;额外 host 也尝试(忽略不存在错误)。
	if len(sql.execs) == 0 || !strings.Contains(sql.execs[0], "ALTER USER 'root'@'localhost' IDENTIFIED BY ?") {
		t.Errorf("root-password exec = %v", sql.execs)
	}
	if audited != 1 {
		t.Errorf("root-password should audit once, got %d", audited)
	}
	// 持久化:新密码应写回设置。
	eff, err := m.ss.effective()
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if eff.MySQLPassword != "NewR00t!" {
		t.Errorf("stored mysql password not updated, got %q", eff.MySQLPassword)
	}
}

func TestRootPasswordPGAdmin(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/postgres/root-password", `{"password":"NewR00t!"}`,
		map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("pg root-password = %d body=%s", rec.Code, rec.Body)
	}
	if len(sql.execs) != 1 || sql.execs[0] != `ALTER ROLE "postgres" WITH PASSWORD ?` {
		t.Errorf("pg root-password exec = %v", sql.execs)
	}
	eff, _ := m.ss.effective()
	if eff.PGPassword != "NewR00t!" {
		t.Errorf("stored pg password not updated, got %q", eff.PGPassword)
	}
}

func TestRootPasswordRequiresConfirm(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	rec := do(router(m), "POST", "/mysql/root-password", `{"password":"x"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("root-password without confirm = %d, want 428", rec.Code)
	}
	if len(sql.execs) != 0 || audited != 0 {
		t.Errorf("unconfirmed root-password must not exec/audit")
	}
}

func TestRootPasswordNonAdmin(t *testing.T) {
	m, _, _ := newTestModule(t, "operator", new(int))
	rec := do(router(m), "POST", "/mysql/root-password", `{"password":"x"}`,
		map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin root-password = %d, want 403", rec.Code)
	}
}

func TestRootPasswordEmptyOrTooLong(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	long := `{"password":"` + strings.Repeat("a", 129) + `"}`
	for _, body := range []string{`{"password":""}`, long} {
		rec := do(router(m), "POST", "/mysql/root-password", body,
			map[string]string{"X-Confirm-Danger": "1"})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s root-password = %d, want 400", body, rec.Code)
		}
	}
	if len(sql.execs) != 0 {
		t.Errorf("invalid password must not exec, got %v", sql.execs)
	}
}

// --- maintain ---

func TestMaintainMySQLAllTables(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	sql.rows = []string{"users", "orders"} // base tables in DB
	rec := do(router(m), "POST", "/mysql/maintain",
		`{"database":"app","action":"optimize"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("maintain = %d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{`"table":"users"`, `"table":"orders"`, `"ok":true`} {
		if !strings.Contains(body, want) {
			t.Errorf("maintain body missing %q: %s", want, body)
		}
	}
	if len(sql.execs) != 2 || !strings.Contains(sql.execs[0], "OPTIMIZE TABLE `app`.`users`") {
		t.Errorf("maintain execs = %v", sql.execs)
	}
	if audited != 1 {
		t.Errorf("maintain should audit once, got %d", audited)
	}
}

func TestMaintainMySQLSingleTable(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/mysql/maintain",
		`{"database":"app","action":"repair","table":"users"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("maintain single = %d body=%s", rec.Code, rec.Body)
	}
	// 指定表 → 不查表清单,直接 REPAIR。
	if len(sql.execs) != 1 || !strings.Contains(sql.execs[0], "REPAIR TABLE `app`.`users`") {
		t.Errorf("maintain single execs = %v", sql.execs)
	}
	if len(sql.queries) != 0 {
		t.Errorf("single-table maintain must not list tables, got %v", sql.queries)
	}
}

func TestMaintainPGAnalyze(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	sql.rows = []string{"t1"}
	rec := do(router(m), "POST", "/postgres/maintain",
		`{"database":"app","action":"analyze"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pg maintain = %d body=%s", rec.Code, rec.Body)
	}
	if len(sql.execs) != 1 || !strings.Contains(sql.execs[0], `ANALYZE "public"."t1"`) {
		t.Errorf("pg maintain execs = %v", sql.execs)
	}
}

func TestMaintainNonAdmin(t *testing.T) {
	m, _, _ := newTestModule(t, "operator", new(int))
	rec := do(router(m), "POST", "/mysql/maintain", `{"database":"app","action":"optimize"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin maintain = %d, want 403", rec.Code)
	}
}

func TestMaintainBadIdentOrAction(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	cases := []string{
		`{"database":"a b","action":"optimize"}`,
		`{"database":"app","action":"bogus"}`,
		`{"database":"app","action":"repair","table":"t;DROP"}`,
	}
	for _, body := range cases {
		rec := do(router(m), "POST", "/mysql/maintain", body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s maintain = %d, want 400", body, rec.Code)
		}
	}
	if len(sql.execs) != 0 {
		t.Errorf("invalid maintain must not exec, got %v", sql.execs)
	}
}

// --- convert-charset (mysql only) ---

func TestConvertCharsetAdmin(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	sql.rows = []string{"users", "orders"}
	rec := do(router(m), "POST", "/mysql/convert-charset",
		`{"database":"app","charset":"utf8mb4","collation":"utf8mb4_general_ci"}`,
		map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("convert-charset = %d body=%s", rec.Code, rec.Body)
	}
	// ALTER DATABASE + 每表 CONVERT
	if len(sql.execs) != 3 {
		t.Fatalf("convert-charset execs = %v", sql.execs)
	}
	if !strings.Contains(sql.execs[0], "ALTER DATABASE `app` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci") {
		t.Errorf("alter database = %q", sql.execs[0])
	}
	if !strings.Contains(sql.execs[1], "ALTER TABLE `app`.`users` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci") {
		t.Errorf("convert table = %q", sql.execs[1])
	}
	body := rec.Body.String()
	for _, want := range []string{`"table":"users"`, `"table":"orders"`, `"ok":true`} {
		if !strings.Contains(body, want) {
			t.Errorf("convert body missing %q: %s", want, body)
		}
	}
	if audited != 1 {
		t.Errorf("convert-charset should audit once, got %d", audited)
	}
}

func TestConvertCharsetRequiresConfirm(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	rec := do(router(m), "POST", "/mysql/convert-charset",
		`{"database":"app","charset":"utf8mb4","collation":"utf8mb4_general_ci"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("convert without confirm = %d, want 428", rec.Code)
	}
	if len(sql.execs) != 0 || audited != 0 {
		t.Errorf("unconfirmed convert must not exec/audit")
	}
}

func TestConvertCharsetNonAdmin(t *testing.T) {
	m, _, _ := newTestModule(t, "operator", new(int))
	rec := do(router(m), "POST", "/mysql/convert-charset",
		`{"database":"app","charset":"utf8mb4","collation":"utf8mb4_general_ci"}`,
		map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin convert = %d, want 403", rec.Code)
	}
}

func TestConvertCharsetBadInput(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	cases := []string{
		`{"database":"a b","charset":"utf8mb4","collation":"utf8mb4_general_ci"}`,
		`{"database":"app","charset":"utf8mb4;DROP","collation":"utf8mb4_general_ci"}`,
		`{"database":"app","charset":"utf8mb4","collation":""}`,
	}
	for _, body := range cases {
		rec := do(router(m), "POST", "/mysql/convert-charset", body,
			map[string]string{"X-Confirm-Danger": "1"})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s convert = %d, want 400", body, rec.Code)
		}
	}
	if len(sql.execs) != 0 {
		t.Errorf("invalid convert must not exec, got %v", sql.execs)
	}
}

// convert-charset 只挂 mysql,postgres 无此路由。
func TestConvertCharsetNoPGRoute(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/postgres/convert-charset",
		`{"database":"app","charset":"utf8","collation":"C"}`,
		map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("pg convert-charset = %d, want 404", rec.Code)
	}
}
