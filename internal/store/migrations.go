package store

// migrations 按顺序执行,幂等(IF NOT EXISTS)。新增迁移往末尾追加。
var migrations = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		username   TEXT NOT NULL UNIQUE,
		pass_hash  TEXT NOT NULL,
		role       TEXT NOT NULL DEFAULT 'admin',
		created_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS refresh_tokens (
		id         TEXT PRIMARY KEY,
		user_id    INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		revoked    INTEGER NOT NULL DEFAULT 0,
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`,
	`CREATE TABLE IF NOT EXISTS audit_log (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		ts        INTEGER NOT NULL,
		user_id   INTEGER,
		action    TEXT NOT NULL,
		detail    TEXT,
		source_ip TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS module_state (
		id      TEXT PRIMARY KEY,
		enabled INTEGER NOT NULL DEFAULT 0
	)`,
}
