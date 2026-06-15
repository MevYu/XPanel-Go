package files

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// ErrShareNotFound 表示 token 不存在(或已被撤销)。
var ErrShareNotFound = errors.New("share not found")

// Share 是一条外链分享记录。RelPath 相对面板根,作为该分享的独立子树根。
type Share struct {
	Token        string
	RelPath      string // 相对面板文件根的路径,公开访问以此为新根
	OwnerID      int64
	PassHash     string // argon2 PHC;空串表示无密码
	AllowList    bool   // 是否允许列目录;false 时仅单文件直下
	ExpiresAt    int64  // unix 秒;0 表示永不过期
	MaxDownloads int64  // 下载次数上限;0 表示不限
	Downloads    int64  // 已下载次数
	CreatedAt    int64
}

// shareSchema 幂等建表。模块自管,不进 store.migrations。
const shareSchema = `CREATE TABLE IF NOT EXISTS file_shares (
	token         TEXT PRIMARY KEY,
	rel_path      TEXT NOT NULL,
	owner_id      INTEGER NOT NULL,
	pass_hash     TEXT NOT NULL DEFAULT '',
	allow_list    INTEGER NOT NULL DEFAULT 0,
	expires_at    INTEGER NOT NULL DEFAULT 0,
	max_downloads INTEGER NOT NULL DEFAULT 0,
	downloads     INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL
)`

// shareStore 封装 file_shares 表的读写,挂在传入的 *store.Store 上。
type shareStore struct{ db *sql.DB }

func newShareStore(st *store.Store) (*shareStore, error) {
	if _, err := st.DB.Exec(shareSchema); err != nil {
		return nil, err
	}
	return &shareStore{db: st.DB}, nil
}

// newToken 生成 192-bit URL-safe 随机 token(不可枚举)。
func newToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *shareStore) create(sh Share) (string, error) {
	tok, err := newToken()
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(
		`INSERT INTO file_shares (token, rel_path, owner_id, pass_hash, allow_list, expires_at, max_downloads, downloads, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		tok, sh.RelPath, sh.OwnerID, sh.PassHash, b2i(sh.AllowList), sh.ExpiresAt, sh.MaxDownloads, time.Now().Unix(),
	)
	if err != nil {
		return "", err
	}
	return tok, nil
}

// get 返回 token 对应的分享;不存在返回 ErrShareNotFound。过期判定交给调用方(公开端点区分 410)。
func (s *shareStore) get(token string) (Share, error) {
	var sh Share
	var allow int64
	err := s.db.QueryRow(
		`SELECT token, rel_path, owner_id, pass_hash, allow_list, expires_at, max_downloads, downloads, created_at
		 FROM file_shares WHERE token = ?`, token,
	).Scan(&sh.Token, &sh.RelPath, &sh.OwnerID, &sh.PassHash, &allow, &sh.ExpiresAt, &sh.MaxDownloads, &sh.Downloads, &sh.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrShareNotFound
	}
	if err != nil {
		return Share{}, err
	}
	sh.AllowList = allow != 0
	return sh, nil
}

// listByOwner 列出某用户创建的分享。
func (s *shareStore) listByOwner(ownerID int64) ([]Share, error) {
	rows, err := s.db.Query(
		`SELECT token, rel_path, owner_id, pass_hash, allow_list, expires_at, max_downloads, downloads, created_at
		 FROM file_shares WHERE owner_id = ? ORDER BY created_at DESC`, ownerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		var sh Share
		var allow int64
		if err := rows.Scan(&sh.Token, &sh.RelPath, &sh.OwnerID, &sh.PassHash, &allow, &sh.ExpiresAt, &sh.MaxDownloads, &sh.Downloads, &sh.CreatedAt); err != nil {
			return nil, err
		}
		sh.AllowList = allow != 0
		out = append(out, sh)
	}
	return out, rows.Err()
}

// revoke 删除分享。onlyOwner 为 true 时仅当 owner 匹配才删;返回是否删除成功。
func (s *shareStore) revoke(token string, requesterID int64, isAdmin bool) (bool, error) {
	var res sql.Result
	var err error
	if isAdmin {
		res, err = s.db.Exec(`DELETE FROM file_shares WHERE token = ?`, token)
	} else {
		res, err = s.db.Exec(`DELETE FROM file_shares WHERE token = ? AND owner_id = ?`, token, requesterID)
	}
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// incDownloadIfAllowed 原子地在未超限时把 downloads +1。
// 返回 true 表示本次计数成功(允许下载);false 表示已达上限。max=0 表示不限。
func (s *shareStore) incDownloadIfAllowed(token string) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE file_shares SET downloads = downloads + 1
		 WHERE token = ? AND (max_downloads = 0 OR downloads < max_downloads)`, token,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
