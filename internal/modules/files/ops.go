package files

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type moveReq struct {
	Src  string `json:"src"`
	Dest string `json:"dest"`
}

// handleMove 移动(剪切)src 到 dest。两端 SafeJoin;dest 已存在则拒绝(明确策略,不覆盖)。
func (m *Module) handleMove(w http.ResponseWriter, r *http.Request) {
	var req moveReq
	if !decodeJSON(w, r, &req) {
		return
	}
	src, err := m.resolve(req.Src)
	if err != nil {
		pathError(w, err)
		return
	}
	dest, err := m.resolve(req.Dest)
	if err != nil {
		pathError(w, err)
		return
	}
	if src == m.root {
		http.Error(w, "refusing to move root", http.StatusBadRequest)
		return
	}
	if _, err := os.Lstat(dest); err == nil {
		http.Error(w, "destination already exists", http.StatusConflict)
		return
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		fsError(w, err)
		return
	}
	if err := moveAcross(src, dest); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.move", req.Src+" -> "+req.Dest)
	w.WriteHeader(http.StatusNoContent)
}

// ---- 目录大小 ----

const (
	dirSizeMaxDepth = 32
	dirSizeTimeout  = 30 * time.Second
)

type dirSizeResp struct {
	Bytes int64 `json:"bytes"`
	Files int64 `json:"files"`
	Dirs  int64 `json:"dirs"`
}

func (m *Module) handleDirSize(w http.ResponseWriter, r *http.Request) {
	abs, err := m.resolve(r.URL.Query().Get("path"))
	if err != nil {
		pathError(w, err)
		return
	}
	fi, err := os.Stat(abs)
	if err != nil {
		fsError(w, err)
		return
	}
	if !fi.IsDir() {
		writeJSON(w, http.StatusOK, dirSizeResp{Bytes: fi.Size(), Files: 1})
		return
	}
	deadline := time.Now().Add(dirSizeTimeout)
	var resp dirSizeResp
	walkSize(abs, 0, deadline, &resp)
	writeJSON(w, http.StatusOK, resp)
}

// walkSize 递归累加目录大小。不跟符号链接(用 Lstat),限深度与超时,尽力而为不报错。
func walkSize(dir string, depth int, deadline time.Time, acc *dirSizeResp) {
	if depth > dirSizeMaxDepth || time.Now().After(deadline) {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			continue // 不跟符号链接,挡循环与越根
		}
		if e.IsDir() {
			acc.Dirs++
			walkSize(filepath.Join(dir, e.Name()), depth+1, deadline, acc)
			continue
		}
		acc.Files++
		acc.Bytes += fi.Size()
	}
}

// ---- 搜索 ----

const (
	searchMaxResults = 500
	searchMaxDepth   = 32
	searchTimeout    = 20 * time.Second
	searchMaxContent = 2 << 20 // 内容搜单文件大小上限 2 MiB
)

// handleSearch 在 path(SafeJoin 根内)下递归搜:name 为文件名 glob,content 为内容子串。
// 两者可单用或同用。不跟符号链接出根,限结果数/深度/超时,内容只搜文本文件。
func (m *Module) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	abs, err := m.resolve(q.Get("path"))
	if err != nil {
		pathError(w, err)
		return
	}
	namePat := q.Get("name")
	content := q.Get("content")
	if namePat == "" && content == "" {
		http.Error(w, "name or content required", http.StatusBadRequest)
		return
	}
	if namePat != "" {
		// 早验 glob 语法,坏 pattern 直接 400 而非静默 0 结果。
		if _, err := filepath.Match(namePat, "x"); err != nil {
			http.Error(w, "invalid name pattern", http.StatusBadRequest)
			return
		}
	}
	contentBytes := []byte(content)
	deadline := time.Now().Add(searchTimeout)
	results := make([]string, 0)
	searchWalk(abs, m.root, 0, deadline, namePat, contentBytes, &results)
	writeJSON(w, http.StatusOK, results)
}

func searchWalk(dir, root string, depth int, deadline time.Time, namePat string, content []byte, results *[]string) {
	if depth > searchMaxDepth || len(*results) >= searchMaxResults || time.Now().After(deadline) {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if len(*results) >= searchMaxResults || time.Now().After(deadline) {
			return
		}
		full := filepath.Join(dir, e.Name())
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			continue // 不跟符号链接,绝不越根
		}
		if e.IsDir() {
			searchWalk(full, root, depth+1, deadline, namePat, content, results)
			continue
		}
		if !matchEntry(full, e.Name(), fi.Size(), namePat, content) {
			continue
		}
		rel, err := filepath.Rel(root, full)
		if err != nil {
			continue
		}
		*results = append(*results, rel)
	}
}

// matchEntry 按 name glob 与/或 content 子串判定文件是否命中。两条件都给时取交集(AND)。
func matchEntry(full, name string, size int64, namePat string, content []byte) bool {
	if namePat != "" {
		ok, err := filepath.Match(namePat, name)
		if err != nil || !ok {
			return false
		}
	}
	if len(content) > 0 {
		return contentMatches(full, size, content)
	}
	return true
}

// contentMatches 读文件查子串。超大小上限或为二进制(含 NUL)则跳过。
func contentMatches(full string, size int64, content []byte) bool {
	if size > searchMaxContent {
		return false
	}
	f, err := os.Open(full)
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, searchMaxContent))
	if err != nil {
		return false
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return false // 二进制不搜
	}
	return bytes.Contains(data, content)
}
