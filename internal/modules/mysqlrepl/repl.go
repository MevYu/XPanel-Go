package mysqlrepl

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// errNoStatus 表示 SHOW SLAVE/MASTER STATUS 返回空(未配置主从)。
var errNoStatus = errors.New("no replication status (not configured)")

// MasterStatus 是 SHOW MASTER STATUS 的关键字段(用于从库 CHANGE MASTER TO)。
type MasterStatus struct {
	File     string `json:"file"`
	Position int64  `json:"position"`
}

// SlaveStatus 是 SHOW SLAVE STATUS 的关键字段(精简,够前端判断健康)。
type SlaveStatus struct {
	IORunning     string `json:"io_running"`      // Slave_IO_Running: Yes/No/Connecting
	SQLRunning    string `json:"sql_running"`     // Slave_SQL_Running: Yes/No
	SecondsBehind *int64 `json:"seconds_behind"`  // Seconds_Behind_Master,NULL → nil
	MasterHost    string `json:"master_host"`     // Master_Host
	MasterLogFile string `json:"master_log_file"` // Master_Log_File
	LastIOError   string `json:"last_io_error"`   // Last_IO_Error
	LastSQLError  string `json:"last_sql_error"`  // Last_SQL_Error
	Healthy       bool   `json:"healthy"`         // IO 与 SQL 线程均 Yes
}

// configureMasterReq 是"在主库建复制用户"的入参。
type configureMasterReq struct {
	ReplUser     string `json:"repl_user"`     // 复制账号(标识符白名单)
	ReplPassword string `json:"repl_password"` // 复制账号口令(转义为字面量)
	SlaveHost    string `json:"slave_host"`    // 允许该从库 host 连接(字面量,'%' 也可)
}

// configureSlaveReq 是"从库指向主库并启动复制"的入参。
type configureSlaveReq struct {
	MasterHost    string `json:"master_host"`
	MasterPort    int    `json:"master_port"`
	ReplUser      string `json:"repl_user"`
	ReplPassword  string `json:"repl_password"`
	MasterLogFile string `json:"master_log_file"`
	MasterLogPos  int64  `json:"master_log_pos"`
}

// masterStatus 读主库的 SHOW MASTER STATUS。
func masterStatus(ctx context.Context, be mysqlBackend) (MasterStatus, error) {
	row, err := be.queryRow(ctx, "SHOW MASTER STATUS")
	if err != nil {
		return MasterStatus{}, err
	}
	if row == nil {
		return MasterStatus{}, errNoStatus
	}
	pos, _ := strconv.ParseInt(row["Position"], 10, 64)
	return MasterStatus{File: row["File"], Position: pos}, nil
}

// slaveStatus 读从库的 SHOW SLAVE STATUS 并解析为精简结构。
func slaveStatus(ctx context.Context, be mysqlBackend) (SlaveStatus, error) {
	row, err := be.queryRow(ctx, "SHOW SLAVE STATUS")
	if err != nil {
		return SlaveStatus{}, err
	}
	if row == nil {
		return SlaveStatus{}, errNoStatus
	}
	return parseSlaveStatus(row), nil
}

// parseSlaveStatus 把 SHOW SLAVE STATUS 行映射成结构。Seconds_Behind_Master 为 NULL
// (字符串空或字面 "NULL")时表示复制断开,置 nil 而非 0。
func parseSlaveStatus(row map[string]string) SlaveStatus {
	st := SlaveStatus{
		IORunning:     row["Slave_IO_Running"],
		SQLRunning:    row["Slave_SQL_Running"],
		MasterHost:    row["Master_Host"],
		MasterLogFile: row["Master_Log_File"],
		LastIOError:   row["Last_IO_Error"],
		LastSQLError:  row["Last_SQL_Error"],
	}
	if v := row["Seconds_Behind_Master"]; v != "" && v != "NULL" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			st.SecondsBehind = &n
		}
	}
	st.Healthy = st.IORunning == "Yes" && st.SQLRunning == "Yes"
	return st
}

// createReplUser 在主库建复制用户并授 REPLICATION SLAVE。
// 用户名白名单+反引号引用;host/口令转义为字符串字面量(无法参数化)。
func createReplUser(ctx context.Context, be mysqlBackend, req configureMasterReq) error {
	qu, err := quoteMySQL(req.ReplUser)
	if err != nil {
		return err
	}
	host := req.SlaveHost
	if host == "" {
		host = "%"
	}
	qhost := quoteStringLiteral(host)
	create := fmt.Sprintf("CREATE USER IF NOT EXISTS %s@%s IDENTIFIED BY %s",
		qu, qhost, quoteStringLiteral(req.ReplPassword))
	if err := be.exec(ctx, create); err != nil {
		return err
	}
	grant := fmt.Sprintf("GRANT REPLICATION SLAVE ON *.* TO %s@%s", qu, qhost)
	return be.exec(ctx, grant)
}

// configureSlave 在从库执行 CHANGE MASTER TO 并 START SLAVE。
// repl_user 白名单引用,host/口令/log_file 转义为字面量,port/pos 为整数(无注入面)。
func configureSlave(ctx context.Context, be mysqlBackend, req configureSlaveReq) error {
	if !validIdent(req.ReplUser) {
		return errInvalidIdent
	}
	stmt := fmt.Sprintf(
		"CHANGE MASTER TO MASTER_HOST=%s, MASTER_PORT=%d, MASTER_USER=%s, MASTER_PASSWORD=%s, MASTER_LOG_FILE=%s, MASTER_LOG_POS=%d",
		quoteStringLiteral(req.MasterHost), req.MasterPort, quoteStringLiteral(req.ReplUser),
		quoteStringLiteral(req.ReplPassword), quoteStringLiteral(req.MasterLogFile), req.MasterLogPos)
	if err := be.exec(ctx, stmt); err != nil {
		return err
	}
	return be.exec(ctx, "START SLAVE")
}

func startSlave(ctx context.Context, be mysqlBackend) error { return be.exec(ctx, "START SLAVE") }
func stopSlave(ctx context.Context, be mysqlBackend) error  { return be.exec(ctx, "STOP SLAVE") }

// resetSlave 清除从库复制配置(危险:STOP + RESET SLAVE ALL)。
func resetSlave(ctx context.Context, be mysqlBackend) error {
	if err := be.exec(ctx, "STOP SLAVE"); err != nil {
		return err
	}
	return be.exec(ctx, "RESET SLAVE ALL")
}
