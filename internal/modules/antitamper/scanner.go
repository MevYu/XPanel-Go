package antitamper

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FileState 是一个受保护文件在某时刻的指纹:内容哈希 + mtime + 权限位。
// Path 为绝对路径。
type FileState struct {
	Path  string `json:"path"`
	Hash  string `json:"hash"`  // SHA-256 hex
	MTime int64  `json:"mtime"` // Unix 秒
	Mode  uint32 `json:"mode"`  // 权限位(os.FileMode 的 perm 部分)
}

// ChangeType 是篡改事件的类型。
type ChangeType string

const (
	ChangeAdded    ChangeType = "added"
	ChangeDeleted  ChangeType = "deleted"
	ChangeModified ChangeType = "modified"
)

// Change 是一次基线对比检出的单个变更。OldHash/NewHash 对 added 仅有 New,
// 对 deleted 仅有 Old,对 modified 两者皆有。
type Change struct {
	Path    string     `json:"path"`
	Type    ChangeType `json:"type"`
	OldHash string     `json:"old_hash"`
	NewHash string     `json:"new_hash"`
}

// hashFile 计算文件内容的 SHA-256。只读打开,绝不执行被监控文件。
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// excluded 报告 rel(相对受保护根的路径,以 "/" 分隔)是否命中任一排除规则。
// 规则用 filepath.Match 语义匹配路径的任一段或完整相对路径。
func excluded(rel string, rules []string) bool {
	rel = filepath.ToSlash(rel)
	segs := strings.Split(rel, "/")
	for _, rule := range rules {
		if rule == "" {
			continue
		}
		if ok, _ := filepath.Match(rule, rel); ok {
			return true
		}
		for _, seg := range segs {
			if ok, _ := filepath.Match(rule, seg); ok {
				return true
			}
		}
	}
	return false
}

// ScanTree 遍历 root 子树,为每个常规文件生成 FileState。
// 跳过目录、符号链接与命中 exclude 规则的路径(只读;绝不执行被监控文件)。
// 返回的 map 以绝对路径为键。root 必须是已存在的绝对路径。
func ScanTree(root string, exclude []string) (map[string]FileState, error) {
	out := map[string]FileState{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if rel != "." && excluded(rel, exclude) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		// 只指纹常规文件:符号链接/设备/socket 等跳过(避免跟随软链逃逸或阻塞)。
		if !d.Type().IsRegular() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		hash, herr := hashFile(path)
		if herr != nil {
			return herr
		}
		out[path] = FileState{
			Path:  path,
			Hash:  hash,
			MTime: info.ModTime().Unix(),
			Mode:  uint32(info.Mode().Perm()),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Diff 对比基线 base 与当前 cur,返回所有变更。
// modified 判定以内容哈希为准(mtime/权限变化不单独算篡改,避免噪声)。
func Diff(base, cur map[string]FileState) []Change {
	var changes []Change
	for path, c := range cur {
		b, ok := base[path]
		if !ok {
			changes = append(changes, Change{Path: path, Type: ChangeAdded, NewHash: c.Hash})
			continue
		}
		if b.Hash != c.Hash {
			changes = append(changes, Change{Path: path, Type: ChangeModified, OldHash: b.Hash, NewHash: c.Hash})
		}
	}
	for path, b := range base {
		if _, ok := cur[path]; !ok {
			changes = append(changes, Change{Path: path, Type: ChangeDeleted, OldHash: b.Hash})
		}
	}
	return changes
}
