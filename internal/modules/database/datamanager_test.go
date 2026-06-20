package database

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func strp(s string) *string { return &s }

func TestTablesAdmin(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	sql.rowMaps = []map[string]string{
		{"name": "users", "rows": "1234"},
		{"name": "orders", "rows": "0"},
	}
	rec := do(router(m), "GET", "/mysql/tables?database=app", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("tables = %d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{`"name":"users"`, `"rows":1234`, `"name":"orders"`} {
		if !strings.Contains(body, want) {
			t.Errorf("tables body missing %q: %s", want, body)
		}
	}
	// 库名作绑定参数,不进 SQL 文本。
	if len(sql.queries) != 1 || strings.Contains(sql.queries[0], "app") {
		t.Errorf("tables query should bind db, got %v", sql.queries)
	}
	if audited != 1 {
		t.Errorf("tables should audit once, got %d", audited)
	}
}

func TestTablesPG(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	sql.rows = []string{"t1", "t2"}
	rec := do(router(m), "GET", "/postgres/tables?database=app", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pg tables = %d", rec.Code)
	}
	if !strings.Contains(sql.queries[0], "table_schema = 'public'") {
		t.Errorf("pg tables query = %v", sql.queries)
	}
	if !strings.Contains(rec.Body.String(), `"name":"t1"`) {
		t.Errorf("pg tables body = %s", rec.Body)
	}
}

func TestTablesBadIdent(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	for _, db := range []string{"a b", "x;DROP", "", "back`tick"} {
		rec := do(router(m), "GET", "/mysql/tables?database="+url.QueryEscape(db), "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("db %q tables = %d, want 400", db, rec.Code)
		}
	}
	if len(sql.queries) != 0 {
		t.Errorf("bad ident must not query, got %v", sql.queries)
	}
}

func TestRowsAdmin(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	sql.tableCol = []string{"id", "name"}
	sql.tableRow = [][]*string{{strp("1"), strp("alice")}, {nil, strp("bob")}}
	sql.rows = []string{"1234"} // COUNT(*)
	rec := do(router(m), "GET", "/mysql/rows?database=app&table=users&limit=10&offset=5", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rows = %d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{`"columns":["id","name"]`, `["1","alice"]`, `[null,"bob"]`, `"total":1234`} {
		if !strings.Contains(body, want) {
			t.Errorf("rows body missing %q: %s", want, body)
		}
	}
	// 限定表名经引用进入 SELECT。
	sel := sql.queries[0]
	if !strings.Contains(sel, "SELECT * FROM `app`.`users`") || !strings.Contains(sel, "LIMIT ? OFFSET ?") {
		t.Errorf("rows select = %q", sel)
	}
	if audited != 1 {
		t.Errorf("rows should audit once, got %d", audited)
	}
}

func TestRowsPG(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	sql.tableCol = []string{"id"}
	rec := do(router(m), "GET", "/postgres/rows?database=app&table=users", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pg rows = %d", rec.Code)
	}
	if !strings.Contains(sql.queries[0], `SELECT * FROM "public"."users"`) {
		t.Errorf("pg rows select = %q", sql.queries[0])
	}
}

func TestRowsBadIdent(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	cases := [][2]string{{"a b", "t"}, {"app", "t;DROP"}, {"app", ""}}
	for _, c := range cases {
		rec := do(router(m), "GET", "/mysql/rows?database="+url.QueryEscape(c[0])+"&table="+url.QueryEscape(c[1]), "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("db=%q table=%q rows = %d, want 400", c[0], c[1], rec.Code)
		}
	}
	if len(sql.queries) != 0 {
		t.Errorf("bad ident must not query, got %v", sql.queries)
	}
}

func TestQueryAdminWithColumns(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	sql.tableCol = []string{"n"}
	sql.tableRow = [][]*string{{strp("1")}}
	rec := do(router(m), "POST", "/mysql/query",
		`{"database":"app","sql":"SELECT 1 AS n"}`, map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("query = %d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"columns":["n"]`) || !strings.Contains(body, `"truncated":false`) {
		t.Errorf("query body = %s", body)
	}
	if audited != 1 {
		t.Errorf("query should audit once, got %d", audited)
	}
}

func TestQueryAdminNoColumns(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	sql.tableCol = nil // DML/DDL: 无结果列
	rec := do(router(m), "POST", "/postgres/query",
		`{"database":"app","sql":"CREATE TABLE t(id int)"}`, map[string]string{"X-Confirm-Danger": "1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("query ddl = %d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"message":"OK"`) {
		t.Errorf("query ddl body = %s", rec.Body)
	}
}

func TestQueryRequiresConfirm(t *testing.T) {
	audited := 0
	m, sql, _ := newTestModule(t, "admin", &audited)
	rec := do(router(m), "POST", "/mysql/query", `{"database":"app","sql":"SELECT 1"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("query without confirm = %d, want 428", rec.Code)
	}
	if len(sql.queries) != 0 || audited != 0 {
		t.Errorf("unconfirmed query must not run/audit")
	}
}

func TestQueryBadIdentAndEmptySQL(t *testing.T) {
	m, _, _ := newTestModule(t, "admin", new(int))
	cases := []string{
		`{"database":"a b","sql":"SELECT 1"}`,
		`{"database":"app","sql":""}`,
		`{"database":"app","sql":"   "}`,
	}
	for _, body := range cases {
		rec := do(router(m), "POST", "/mysql/query", body, map[string]string{"X-Confirm-Danger": "1"})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s query = %d, want 400", body, rec.Code)
		}
	}
}

func TestDataManagerNonAdminForbidden(t *testing.T) {
	m, _, _ := newTestModule(t, "operator", new(int))
	r := router(m)
	cases := []struct{ method, path, body string }{
		{"GET", "/mysql/tables?database=app", ""},
		{"GET", "/mysql/rows?database=app&table=t", ""},
		{"POST", "/mysql/query", `{"database":"app","sql":"SELECT 1"}`},
		{"GET", "/postgres/tables?database=app", ""},
	}
	for _, c := range cases {
		rec := do(r, c.method, c.path, c.body, map[string]string{"X-Confirm-Danger": "1"})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", c.method, c.path, rec.Code)
		}
	}
}
