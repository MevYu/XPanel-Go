package migration

import (
	"errors"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func testStore(t *testing.T) *migrationStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ms, err := newMigrationStore(st)
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func TestSaveSettingsRejectsMaliciousToolPath(t *testing.T) {
	ms := testStore(t)
	bad := []Settings{
		{MysqlDump: "mysqldump; rm -rf /"},
		{PgDump: "../../tmp/evil"},
		{MysqlCLI: "/tmp/evil"},
		{PsqlCLI: "psql evil"},
	}
	for _, in := range bad {
		if err := ms.saveSettings(in); !errors.Is(err, errInvalidToolPath) {
			t.Errorf("saveSettings(%+v) err = %v, want errInvalidToolPath", in, err)
		}
	}
}

func TestSaveSettingsAcceptsSimpleNames(t *testing.T) {
	ms := testStore(t)
	in := Settings{MysqlDump: "mariadb-dump", PgDump: "pg_dump", MysqlCLI: "mariadb", PsqlCLI: "psql"}
	if err := ms.saveSettings(in); err != nil {
		t.Fatalf("saveSettings legit: %v", err)
	}
	got, err := ms.settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.MysqlDump != "mariadb-dump" || got.MysqlCLI != "mariadb" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// 即便非法值被直接写进底层表(绕过 saveSettings),载入时也回落默认名,绝不返回可执行的恶意路径。
func TestSettingsLoadSanitizesPersistedBadPath(t *testing.T) {
	ms := testStore(t)
	if _, err := ms.db.Exec(`INSERT INTO migration_settings
		(id, migration_dir, mysqldump, pgdump, mysql_cli, psql_cli)
		VALUES (1, '', ?, '', ?, '')`, "/tmp/evil;sh", "evil cli"); err != nil {
		t.Fatal(err)
	}
	got, err := ms.settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.MysqlDump != "mysqldump" {
		t.Errorf("MysqlDump = %q, want default mysqldump", got.MysqlDump)
	}
	if got.MysqlCLI != "mysql" {
		t.Errorf("MysqlCLI = %q, want default mysql", got.MysqlCLI)
	}
}
