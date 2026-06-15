package alert

import (
	"database/sql"
	"errors"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// errNotFound 表示按 id 查无记录。
var errNotFound = errors.New("alert: not found")

// ChannelKind 是通知渠道类型。
type ChannelKind string

const (
	ChannelEmail    ChannelKind = "email"
	ChannelWebhook  ChannelKind = "webhook"
	ChannelTelegram ChannelKind = "telegram"
)

func validChannelKind(k ChannelKind) bool {
	switch k {
	case ChannelEmail, ChannelWebhook, ChannelTelegram:
		return true
	}
	return false
}

// Channel 是一个通知渠道。凭证字段(SMTP 密码、webhook/telegram token)落库时
// AES-GCM 加密,API 输出一律屏蔽(Secret 置空,HasSecret 标示是否已设)。
type Channel struct {
	ID   int64       `json:"id"`
	Name string      `json:"name"`
	Kind ChannelKind `json:"kind"`

	// 邮件(SMTP)
	SMTPHost string `json:"smtp_host,omitempty"`
	SMTPPort int    `json:"smtp_port,omitempty"`
	SMTPUser string `json:"smtp_user,omitempty"`
	SMTPFrom string `json:"smtp_from,omitempty"`
	SMTPTo   string `json:"smtp_to,omitempty"`

	// Webhook
	WebhookURL string `json:"webhook_url,omitempty"`

	// Telegram
	TelegramChatID string `json:"telegram_chat_id,omitempty"`

	// Secret 是写入用凭证明文:SMTP 为密码、webhook 为 bearer token、telegram 为 bot token。
	// 落库加密;读出时一律置空。
	Secret    string `json:"secret,omitempty"`
	HasSecret bool   `json:"has_secret"`

	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

// Rule 是一条告警规则。
type Rule struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Metric      string  `json:"metric"`
	Comparator  string  `json:"comparator"`
	Threshold   float64 `json:"threshold"`
	DurationSec int     `json:"duration_sec"` // 持续超阈值多久才触发
	ChannelID   int64   `json:"channel_id"`
	Enabled     bool    `json:"enabled"`
	CreatedAt   int64   `json:"created_at"`
	UpdatedAt   int64   `json:"updated_at"`
}

// History 是一条告警触发历史。
type History struct {
	ID        int64   `json:"id"`
	RuleID    int64   `json:"rule_id"`
	RuleName  string  `json:"rule_name"`
	Metric    string  `json:"metric"`
	Value     float64 `json:"value"`
	Threshold float64 `json:"threshold"`
	Notified  bool    `json:"notified"` // 通知是否发送成功
	Detail    string  `json:"detail"`
	FiredAt   int64   `json:"fired_at"`
}

const createChannelsTable = `CREATE TABLE IF NOT EXISTS alert_channels (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	name             TEXT NOT NULL,
	kind             TEXT NOT NULL,
	smtp_host        TEXT NOT NULL DEFAULT '',
	smtp_port        INTEGER NOT NULL DEFAULT 0,
	smtp_user        TEXT NOT NULL DEFAULT '',
	smtp_from        TEXT NOT NULL DEFAULT '',
	smtp_to          TEXT NOT NULL DEFAULT '',
	webhook_url      TEXT NOT NULL DEFAULT '',
	telegram_chat_id TEXT NOT NULL DEFAULT '',
	secret_enc       TEXT NOT NULL DEFAULT '',
	created_at       INTEGER NOT NULL,
	updated_at       INTEGER NOT NULL
)`

const createRulesTable = `CREATE TABLE IF NOT EXISTS alert_rules (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL,
	metric       TEXT NOT NULL,
	comparator   TEXT NOT NULL,
	threshold    REAL NOT NULL,
	duration_sec INTEGER NOT NULL DEFAULT 0,
	channel_id   INTEGER NOT NULL,
	enabled      INTEGER NOT NULL DEFAULT 1,
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL
)`

const createHistoryTable = `CREATE TABLE IF NOT EXISTS alert_history (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_id    INTEGER NOT NULL,
	rule_name  TEXT NOT NULL,
	metric     TEXT NOT NULL,
	value      REAL NOT NULL,
	threshold  REAL NOT NULL,
	notified   INTEGER NOT NULL DEFAULT 0,
	detail     TEXT NOT NULL DEFAULT '',
	fired_at   INTEGER NOT NULL
)`

const createSettingsTable = `CREATE TABLE IF NOT EXISTS alert_settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
)`

// alertStore 自建表,管理渠道(凭证加密)、规则、历史与模块设置。不动中央 migrations。
type alertStore struct {
	db   *sql.DB
	cryp *cryptor
}

func newAlertStore(st *store.Store, cryp *cryptor) (*alertStore, error) {
	for _, q := range []string{createChannelsTable, createRulesTable, createHistoryTable, createSettingsTable} {
		if _, err := st.DB.Exec(q); err != nil {
			return nil, err
		}
	}
	return &alertStore{db: st.DB, cryp: cryp}, nil
}

// ---- channels ----

const channelCols = `id, name, kind, smtp_host, smtp_port, smtp_user, smtp_from, smtp_to,
	webhook_url, telegram_chat_id, secret_enc, created_at, updated_at`

// scanChannelEnc scans a channel row, returning the still-encrypted secret separately.
func scanChannelEnc(sc scanner) (Channel, string, error) {
	var c Channel
	var enc string
	err := sc.Scan(&c.ID, &c.Name, &c.Kind, &c.SMTPHost, &c.SMTPPort, &c.SMTPUser, &c.SMTPFrom, &c.SMTPTo,
		&c.WebhookURL, &c.TelegramChatID, &enc, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return Channel{}, "", err
	}
	c.HasSecret = enc != ""
	return c, enc, nil
}

// listChannels 返回所有渠道,Secret 置空(屏蔽)。
func (s *alertStore) listChannels() ([]Channel, error) {
	rows, err := s.db.Query(`SELECT ` + channelCols + ` FROM alert_channels ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		c, _, err := scanChannelEnc(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// getChannel 返回单个渠道,Secret 置空(屏蔽)。
func (s *alertStore) getChannel(id int64) (Channel, error) {
	c, _, err := s.getChannelEnc(id)
	return c, err
}

// getChannelEnc 返回渠道及其解密后的明文凭证(供内部发送用,绝不经 API 输出)。
func (s *alertStore) getChannelEnc(id int64) (Channel, string, error) {
	row := s.db.QueryRow(`SELECT `+channelCols+` FROM alert_channels WHERE id = ?`, id)
	c, enc, err := scanChannelEnc(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, "", errNotFound
	}
	if err != nil {
		return Channel{}, "", err
	}
	plain, err := s.cryp.decrypt(enc)
	if err != nil {
		return Channel{}, "", err
	}
	return c, plain, nil
}

// createChannel 加密凭证后落库,返回新 id。
func (s *alertStore) createChannel(c Channel) (int64, error) {
	enc, err := s.cryp.encrypt(c.Secret)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO alert_channels
		(name, kind, smtp_host, smtp_port, smtp_user, smtp_from, smtp_to,
		 webhook_url, telegram_chat_id, secret_enc, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Name, c.Kind, c.SMTPHost, c.SMTPPort, c.SMTPUser, c.SMTPFrom, c.SMTPTo,
		c.WebhookURL, c.TelegramChatID, enc, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// updateChannel 覆盖渠道。Secret 非空则重新加密;为空则保留原密文(不清空)。
func (s *alertStore) updateChannel(c Channel) error {
	prevEnc, err := s.rawSecret(c.ID)
	if err != nil {
		return err
	}
	enc := prevEnc
	if c.Secret != "" {
		enc, err = s.cryp.encrypt(c.Secret)
		if err != nil {
			return err
		}
	}
	now := time.Now().Unix()
	_, err = s.db.Exec(`UPDATE alert_channels SET
		name=?, kind=?, smtp_host=?, smtp_port=?, smtp_user=?, smtp_from=?, smtp_to=?,
		webhook_url=?, telegram_chat_id=?, secret_enc=?, updated_at=? WHERE id=?`,
		c.Name, c.Kind, c.SMTPHost, c.SMTPPort, c.SMTPUser, c.SMTPFrom, c.SMTPTo,
		c.WebhookURL, c.TelegramChatID, enc, now, c.ID)
	return err
}

// rawSecret 取当前落库的密文凭证(无行返回 errNotFound)。
func (s *alertStore) rawSecret(id int64) (string, error) {
	var enc string
	err := s.db.QueryRow(`SELECT secret_enc FROM alert_channels WHERE id = ?`, id).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errNotFound
	}
	return enc, err
}

func (s *alertStore) deleteChannel(id int64) error {
	_, err := s.db.Exec(`DELETE FROM alert_channels WHERE id = ?`, id)
	return err
}

// ---- rules ----

const ruleCols = `id, name, metric, comparator, threshold, duration_sec, channel_id, enabled, created_at, updated_at`

func scanRule(sc scanner) (Rule, error) {
	var r Rule
	var enabled int
	err := sc.Scan(&r.ID, &r.Name, &r.Metric, &r.Comparator, &r.Threshold, &r.DurationSec,
		&r.ChannelID, &enabled, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return Rule{}, err
	}
	r.Enabled = enabled != 0
	return r, nil
}

func (s *alertStore) listRules() ([]Rule, error) {
	rows, err := s.db.Query(`SELECT ` + ruleCols + ` FROM alert_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// listEnabledRules 仅返回启用的规则(后台评估用)。
func (s *alertStore) listEnabledRules() ([]Rule, error) {
	all, err := s.listRules()
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, r := range all {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *alertStore) getRule(id int64) (Rule, error) {
	row := s.db.QueryRow(`SELECT `+ruleCols+` FROM alert_rules WHERE id = ?`, id)
	r, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, errNotFound
	}
	return r, err
}

func (s *alertStore) createRule(r Rule) (int64, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO alert_rules
		(name, metric, comparator, threshold, duration_sec, channel_id, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Metric, r.Comparator, r.Threshold, r.DurationSec, r.ChannelID, boolToInt(r.Enabled), now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *alertStore) updateRule(r Rule) error {
	now := time.Now().Unix()
	res, err := s.db.Exec(`UPDATE alert_rules SET
		name=?, metric=?, comparator=?, threshold=?, duration_sec=?, channel_id=?, enabled=?, updated_at=?
		WHERE id=?`,
		r.Name, r.Metric, r.Comparator, r.Threshold, r.DurationSec, r.ChannelID, boolToInt(r.Enabled), now, r.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *alertStore) deleteRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM alert_rules WHERE id = ?`, id)
	return err
}

// ---- history ----

func (s *alertStore) addHistory(h History) error {
	_, err := s.db.Exec(`INSERT INTO alert_history
		(rule_id, rule_name, metric, value, threshold, notified, detail, fired_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		h.RuleID, h.RuleName, h.Metric, h.Value, h.Threshold, boolToInt(h.Notified), h.Detail, h.FiredAt)
	return err
}

// listHistory 返回最近 limit 条历史(按时间倒序)。
func (s *alertStore) listHistory(limit int) ([]History, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, rule_id, rule_name, metric, value, threshold, notified, detail, fired_at
		FROM alert_history ORDER BY fired_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []History
	for rows.Next() {
		var h History
		var notified int
		if err := rows.Scan(&h.ID, &h.RuleID, &h.RuleName, &h.Metric, &h.Value, &h.Threshold,
			&notified, &h.Detail, &h.FiredAt); err != nil {
			return nil, err
		}
		h.Notified = notified != 0
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---- settings ----

const (
	settingIntervalSec = "interval_sec"
	settingSilenceSec  = "silence_sec"
)

// loadSettings 读设置,缺失的 key 回退默认值。
func (s *alertStore) loadSettings() (Settings, error) {
	out := DefaultSettings()
	rows, err := s.db.Query(`SELECT key, value FROM alert_settings`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return out, err
		}
		switch k {
		case settingIntervalSec:
			out.IntervalSec = atoiDefault(v, out.IntervalSec)
		case settingSilenceSec:
			out.SilenceSec = atoiDefault(v, out.SilenceSec)
		}
	}
	return out, rows.Err()
}

func (s *alertStore) saveSettings(set Settings) error {
	const q = `INSERT INTO alert_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	if _, err := s.db.Exec(q, settingIntervalSec, itoa(set.IntervalSec)); err != nil {
		return err
	}
	_, err := s.db.Exec(q, settingSilenceSec, itoa(set.SilenceSec))
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
