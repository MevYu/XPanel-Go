package mysqlrepl

import (
	"context"
	"errors"
	"testing"
)

func TestParseSlaveStatusHealthy(t *testing.T) {
	st := parseSlaveStatus(map[string]string{
		"Slave_IO_Running":      "Yes",
		"Slave_SQL_Running":     "Yes",
		"Seconds_Behind_Master": "0",
		"Master_Host":           "10.0.0.1",
		"Master_Log_File":       "binlog.000003",
	})
	if !st.Healthy {
		t.Error("both threads Yes should be healthy")
	}
	if st.SecondsBehind == nil || *st.SecondsBehind != 0 {
		t.Errorf("seconds_behind = %v, want 0", st.SecondsBehind)
	}
	if st.MasterHost != "10.0.0.1" || st.MasterLogFile != "binlog.000003" {
		t.Errorf("master fields wrong: %+v", st)
	}
}

func TestParseSlaveStatusLagging(t *testing.T) {
	st := parseSlaveStatus(map[string]string{
		"Slave_IO_Running":      "Yes",
		"Slave_SQL_Running":     "Yes",
		"Seconds_Behind_Master": "120",
	})
	if st.SecondsBehind == nil || *st.SecondsBehind != 120 {
		t.Errorf("seconds_behind = %v, want 120", st.SecondsBehind)
	}
}

func TestParseSlaveStatusBroken(t *testing.T) {
	// IO 停 + Seconds_Behind_Master NULL → 不健康、SecondsBehind nil
	for _, nullVal := range []string{"NULL", ""} {
		st := parseSlaveStatus(map[string]string{
			"Slave_IO_Running":      "No",
			"Slave_SQL_Running":     "Yes",
			"Seconds_Behind_Master": nullVal,
			"Last_IO_Error":         "error connecting to master",
		})
		if st.Healthy {
			t.Errorf("IO=No should be unhealthy (null=%q)", nullVal)
		}
		if st.SecondsBehind != nil {
			t.Errorf("NULL seconds should be nil, got %v", st.SecondsBehind)
		}
		if st.LastIOError == "" {
			t.Error("last_io_error should be surfaced")
		}
	}
}

func TestMasterStatusNoRows(t *testing.T) {
	be := &mockBackend{rows: map[string]map[string]string{}} // SHOW MASTER STATUS → nil
	if _, err := masterStatus(context.Background(), be); !errors.Is(err, errNoStatus) {
		t.Errorf("empty master status should be errNoStatus, got %v", err)
	}
}

func TestSlaveStatusNoRows(t *testing.T) {
	be := &mockBackend{}
	if _, err := slaveStatus(context.Background(), be); !errors.Is(err, errNoStatus) {
		t.Errorf("empty slave status should be errNoStatus, got %v", err)
	}
}

func TestCreateReplUserSQL(t *testing.T) {
	be := &mockBackend{}
	err := createReplUser(context.Background(), be, configureMasterReq{
		ReplUser: "repl", ReplPassword: "p@ss", SlaveHost: "10.0.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"CREATE USER IF NOT EXISTS `repl`@'10.0.0.2' IDENTIFIED BY 'p@ss'",
		"GRANT REPLICATION SLAVE ON *.* TO `repl`@'10.0.0.2'",
	}
	assertExecs(t, be, want)
}

func TestCreateReplUserDefaultsHostWildcard(t *testing.T) {
	be := &mockBackend{}
	_ = createReplUser(context.Background(), be, configureMasterReq{ReplUser: "repl", ReplPassword: "p"})
	if be.execs[0] != "CREATE USER IF NOT EXISTS `repl`@'%' IDENTIFIED BY 'p'" {
		t.Errorf("empty host should default to '%%': %v", be.execs)
	}
}

func TestCreateReplUserRejectsBadIdent(t *testing.T) {
	be := &mockBackend{}
	err := createReplUser(context.Background(), be, configureMasterReq{ReplUser: "bad;user", ReplPassword: "p"})
	if !errors.Is(err, errInvalidIdent) {
		t.Errorf("bad ident should error, got %v", err)
	}
	if len(be.execs) != 0 {
		t.Errorf("rejected ident must not reach SQL: %v", be.execs)
	}
}

func TestConfigureSlaveSQL(t *testing.T) {
	be := &mockBackend{}
	err := configureSlave(context.Background(), be, configureSlaveReq{
		MasterHost: "10.0.0.1", MasterPort: 3306, ReplUser: "repl",
		ReplPassword: "p'w", MasterLogFile: "binlog.000003", MasterLogPos: 154,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"CHANGE MASTER TO MASTER_HOST='10.0.0.1', MASTER_PORT=3306, MASTER_USER='repl', MASTER_PASSWORD='p''w', MASTER_LOG_FILE='binlog.000003', MASTER_LOG_POS=154",
		"START SLAVE",
	}
	assertExecs(t, be, want)
}

func TestConfigureSlaveRejectsBadUser(t *testing.T) {
	be := &mockBackend{}
	err := configureSlave(context.Background(), be, configureSlaveReq{ReplUser: "x;y", MasterHost: "h", MasterPort: 3306})
	if !errors.Is(err, errInvalidIdent) {
		t.Errorf("bad repl_user should error, got %v", err)
	}
	if len(be.execs) != 0 {
		t.Errorf("must not reach SQL: %v", be.execs)
	}
}

func TestResetSlaveSQL(t *testing.T) {
	be := &mockBackend{}
	if err := resetSlave(context.Background(), be); err != nil {
		t.Fatal(err)
	}
	assertExecs(t, be, []string{"STOP SLAVE", "RESET SLAVE ALL"})
}

func assertExecs(t *testing.T, be *mockBackend, want []string) {
	t.Helper()
	if len(be.execs) != len(want) {
		t.Fatalf("execs = %v, want %v", be.execs, want)
	}
	for i, w := range want {
		if be.execs[i] != w {
			t.Errorf("exec[%d] = %q, want %q", i, be.execs[i], w)
		}
	}
}
