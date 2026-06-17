package files

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// trashDirName 是面板根内的回收站目录名。软删的条目移到这里,原路径记在 SQLite。
const trashDirName = ".xpanel-trash"

// trashSchema 幂等建表;记录每个软删条目的原相对路径与删除时间。
const trashSchema = `CREATE TABLE IF NOT EXISTS file_trash (
	id            TEXT PRIMARY KEY,
	orig_rel      TEXT NOT NULL,
	is_dir        INTEGER NOT NULL DEFAULT 0,
	size          INTEGER NOT NULL DEFAULT 0,
	deleted_at    INTEGER NOT NULL
)`

type trashItem struct {
	ID        string `json:"id"`
	OrigPath  string `json:"orig_path"` // 原相对路径(相对面板根)
	IsDir     bool   `json:"is_dir"`
	Size      int64  `json:"size"`
	DeletedAt int64  `json:"deleted_at"`
}

func (m *Module) trashStore() *sql.DB { return m.shares.db }

// ensureTrashSchema 幂等建回收站表。在每个回收站端点入口调用,避免改 New 的失败路径。
func (m *Module) ensureTrashSchema() error {
	_, err := m.trashStore().Exec(trashSchema)
	return err
}

// newTrashID 生成不可枚举的回收站条目 id(同时用作回收站内的存储文件名)。
func newTrashID() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// handleDelete 软删:把目标移进回收站目录,原路径与删除时间入库。保留真删能力给清空。
func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	if err := m.ensureTrashSchema(); err != nil {
		http.Error(w, "trash init failed", http.StatusInternalServerError)
		return
	}
	rel := r.URL.Query().Get("path")
	abs, err := m.resolve(rel)
	if err != nil {
		pathError(w, err)
		return
	}
	if abs == m.root {
		http.Error(w, "refusing to delete root", http.StatusBadRequest)
		return
	}
	if abs == m.trash || isWithin(m.trash, abs) {
		http.Error(w, "cannot delete trash directory", http.StatusBadRequest)
		return
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		fsError(w, err)
		return
	}
	if err := os.MkdirAll(m.trash, 0o700); err != nil {
		fsError(w, err)
		return
	}
	id, err := newTrashID()
	if err != nil {
		http.Error(w, "trash id failed", http.StatusInternalServerError)
		return
	}
	dest := filepath.Join(m.trash, id)
	if err := moveAcross(abs, dest); err != nil {
		fsError(w, err)
		return
	}
	_, err = m.trashStore().Exec(
		`INSERT INTO file_trash (id, orig_rel, is_dir, size, deleted_at) VALUES (?, ?, ?, ?, ?)`,
		id, normalizeRel(rel), b2i(fi.IsDir()), fi.Size(), time.Now().Unix(),
	)
	if err != nil {
		http.Error(w, "trash record failed", http.StatusInternalServerError)
		return
	}
	m.audit(r, "files.delete", rel)
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleTrashList(w http.ResponseWriter, r *http.Request) {
	if err := m.ensureTrashSchema(); err != nil {
		http.Error(w, "trash init failed", http.StatusInternalServerError)
		return
	}
	rows, err := m.trashStore().Query(
		`SELECT id, orig_rel, is_dir, size, deleted_at FROM file_trash ORDER BY deleted_at DESC`)
	if err != nil {
		http.Error(w, "trash list failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := make([]trashItem, 0)
	for rows.Next() {
		var it trashItem
		var isDir int64
		if err := rows.Scan(&it.ID, &it.OrigPath, &isDir, &it.Size, &it.DeletedAt); err != nil {
			http.Error(w, "trash scan failed", http.StatusInternalServerError)
			return
		}
		it.IsDir = isDir != 0
		out = append(out, it)
	}
	writeJSON(w, http.StatusOK, out)
}

type trashRestoreReq struct {
	ID string `json:"id"`
}

// handleTrashRestore 还原:把回收站条目移回原相对路径(经 SafeJoin),删记录。
func (m *Module) handleTrashRestore(w http.ResponseWriter, r *http.Request) {
	if err := m.ensureTrashSchema(); err != nil {
		http.Error(w, "trash init failed", http.StatusInternalServerError)
		return
	}
	var req trashRestoreReq
	if !decodeJSON(w, r, &req) {
		return
	}
	var origRel string
	err := m.trashStore().QueryRow(
		`SELECT orig_rel FROM file_trash WHERE id = ?`, req.ID).Scan(&origRel)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "trash item not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "trash lookup failed", http.StatusInternalServerError)
		return
	}
	dest, err := m.resolve(origRel)
	if err != nil {
		pathError(w, err)
		return
	}
	if _, err := os.Lstat(dest); err == nil {
		http.Error(w, "restore target already exists", http.StatusConflict)
		return
	}
	src := filepath.Join(m.trash, req.ID)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		fsError(w, err)
		return
	}
	if err := moveAcross(src, dest); err != nil {
		fsError(w, err)
		return
	}
	if _, err := m.trashStore().Exec(`DELETE FROM file_trash WHERE id = ?`, req.ID); err != nil {
		http.Error(w, "trash record cleanup failed", http.StatusInternalServerError)
		return
	}
	m.audit(r, "files.trash.restore", origRel)
	w.WriteHeader(http.StatusNoContent)
}

// handleTrashEmpty 清空回收站:真删全部条目。危险操作,admin + X-Confirm-Danger。
func (m *Module) handleTrashEmpty(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Confirm-Danger") == "" {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	if err := m.ensureTrashSchema(); err != nil {
		http.Error(w, "trash init failed", http.StatusInternalServerError)
		return
	}
	// 真删回收站目录全部内容,再清表。回收站目录本身是面板根内的固定路径,不经用户输入。
	entries, err := os.ReadDir(m.trash)
	if err != nil && !os.IsNotExist(err) {
		fsError(w, err)
		return
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(m.trash, e.Name())); err != nil {
			fsError(w, err)
			return
		}
	}
	if _, err := m.trashStore().Exec(`DELETE FROM file_trash`); err != nil {
		http.Error(w, "trash clear failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "files.trash.empty", "all", m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// moveAcross 把 src 移到 dst;同设备走 rename,跨设备(EXDEV)回退 copy+remove。
func moveAcross(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if !isCrossDevice(err) {
		return err
	}
	if err := copyPath(src, dst); err != nil {
		return err
	}
	return os.RemoveAll(src)
}

// isWithin 报告 p 是否在 root 子树内(纯词法,二者须为 Clean 绝对路径)。
func isWithin(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !hasDotDotPrefix(rel)
}

func hasDotDotPrefix(rel string) bool {
	return len(rel) >= 3 && rel[0] == '.' && rel[1] == '.' && rel[2] == filepath.Separator
}
