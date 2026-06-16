package database

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestCreateDatabaseWithCharsetCollation(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/mysql/databases",
		`{"database":"shop","charset":"utf8mb4","collation":"utf8mb4_unicode_ci"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("create = %d body=%s", rec.Code, rec.Body)
	}
	want := "CREATE DATABASE `shop` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
	if len(sql.execs) != 1 || sql.execs[0] != want {
		t.Errorf("exec = %v, want %q", sql.execs, want)
	}
}

func TestCreateDatabasePGEncoding(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/postgres/databases",
		`{"database":"shop","charset":"UTF8"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("pg create = %d", rec.Code)
	}
	if sql.execs[0] != `CREATE DATABASE "shop" ENCODING 'UTF8'` {
		t.Errorf("pg exec = %v", sql.execs)
	}
}

func TestCreateDatabaseRejectsBadCharset(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	for _, body := range []string{
		`{"database":"d","charset":"utf8; DROP"}`,
		`{"database":"d","collation":"a b"}`,
	} {
		rec := do(router(m), "POST", "/mysql/databases", body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s = %d, want 400", body, rec.Code)
		}
	}
	if len(sql.execs) != 0 {
		t.Errorf("bad charset must not reach SQL, got %v", sql.execs)
	}
}

func TestCreateUserWithHost(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	rec := do(router(m), "POST", "/mysql/users",
		`{"user":"alice","password":"pw","host":"10.0.0.5"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("create user = %d body=%s", rec.Code, rec.Body)
	}
	want := "CREATE USER `alice`@'10.0.0.5' IDENTIFIED BY 'pw'"
	if sql.execs[0] != want {
		t.Errorf("exec = %v, want %q", sql.execs, want)
	}
}

func TestCreateUserDefaultHostWildcard(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	do(router(m), "POST", "/mysql/users", `{"user":"bob","password":"pw"}`, nil)
	if sql.execs[0] != "CREATE USER `bob`@'%' IDENTIFIED BY 'pw'" {
		t.Errorf("default host exec = %v", sql.execs)
	}
}

func TestGrantRevokeWithHost(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	do(router(m), "POST", "/mysql/grant", `{"database":"app","user":"alice","host":"localhost"}`, nil)
	do(router(m), "POST", "/mysql/revoke", `{"database":"app","user":"alice","host":"localhost"}`, nil)
	want := []string{
		"GRANT ALL PRIVILEGES ON `app`.* TO `alice`@'localhost'",
		"REVOKE ALL PRIVILEGES ON `app`.* FROM `alice`@'localhost'",
	}
	for i, w := range want {
		if sql.execs[i] != w {
			t.Errorf("exec[%d] = %q, want %q", i, sql.execs[i], w)
		}
	}
}

func TestInjectionInHostRejected(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	for _, host := range []string{"a' OR '1", "x;y", "has space"} {
		body := `{"user":"alice","password":"pw","host":"` + host + `"}`
		rec := do(router(m), "POST", "/mysql/users", body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("host %q = %d, want 400", host, rec.Code)
		}
	}
	if len(sql.execs) != 0 {
		t.Errorf("bad host must not reach SQL, got %v", sql.execs)
	}
}

func TestListUsersWithHost(t *testing.T) {
	m, sql, _ := newTestModule(t, "admin", new(int))
	sql.rowMaps = []map[string]string{
		{"user": "root", "host": "localhost"},
		{"user": "alice", "host": "%"},
	}
	rec := do(router(m), "GET", "/mysql/users", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list users = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"host":"localhost"`) || !strings.Contains(body, `"user":"alice"`) {
		t.Errorf("list users body = %s", body)
	}
}

func TestValidHostAndCharset(t *testing.T) {
	goodHost := []string{"%", "localhost", "10.0.0.1", "192.168.%", "db.internal", "::1"}
	for _, h := range goodHost {
		if !validHost(h) {
			t.Errorf("validHost(%q) = false, want true", h)
		}
	}
	badHost := []string{"", "a b", "x;y", "a'b", "a|b"}
	for _, h := range badHost {
		if validHost(h) {
			t.Errorf("validHost(%q) = true, want false", h)
		}
	}
	if !validCharset("utf8mb4_unicode_ci") || validCharset("utf8; x") {
		t.Error("validCharset whitelist wrong")
	}
}

func TestValidToolPath(t *testing.T) {
	good := []string{"mysqldump", "/usr/bin/pg_dump", "/opt/mariadb/bin/mysql"}
	for _, p := range good {
		if !validToolPath(p) {
			t.Errorf("validToolPath(%q) = false, want true", p)
		}
	}
	bad := []string{"", "mysqldump; rm -rf /", "a|b", "dump $(x)", "a b", "`cmd`"}
	for _, p := range bad {
		if validToolPath(p) {
			t.Errorf("validToolPath(%q) = true, want false", p)
		}
	}
}

func TestExportCmdCredentialsNotInArgv(t *testing.T) {
	s := defaultSettings()
	s.MySQLPassword = "topsecret"
	s.PGPassword = "pgsecret"
	cmd, env, err := exportCmd(context.Background(), dialectMySQL, "app", s)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range cmd.Args {
		if strings.Contains(a, "topsecret") {
			t.Errorf("mysql password leaked into argv: %v", cmd.Args)
		}
	}
	if !envHas(env, "MYSQL_PWD=topsecret") {
		t.Errorf("MYSQL_PWD not in env: %v", env)
	}
	cmd, env, err = exportCmd(context.Background(), dialectPG, "app", s)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range cmd.Args {
		if strings.Contains(a, "pgsecret") {
			t.Errorf("pg password leaked into argv: %v", cmd.Args)
		}
	}
	if !envHas(env, "PGPASSWORD=pgsecret") {
		t.Errorf("PGPASSWORD not in env: %v", env)
	}
}

func TestExportCmdRejectsBadToolPath(t *testing.T) {
	s := defaultSettings()
	s.MySQLDumpBin = "mysqldump; rm -rf /"
	if _, _, err := exportCmd(context.Background(), dialectMySQL, "app", s); err != errInvalidToolPath {
		t.Errorf("bad tool path err = %v, want errInvalidToolPath", err)
	}
}

func envHas(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}
