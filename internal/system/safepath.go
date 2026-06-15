package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrPathEscape 表示请求路径在清理/符号链接解析后逃出了允许的根目录。
var ErrPathEscape = errors.New("path escapes root")

// SafeJoin 把不可信的相对路径 rel 限定在 root 子树内,返回 root 内的绝对路径。
//
// 防御层次:
//  1. rel 经 filepath.Clean 后,以 root 为基拼出候选路径,再确认仍以 root 为前缀
//     (挡掉 "../"、绝对路径、多重 "..")。
//  2. 解析候选路径已存在部分的真实路径(EvalSymlinks),确认真实路径仍在 root 内
//     (挡掉指向 root 外的符号链接逃逸)。
//  3. 若最终段本身是符号链接(含指向 root 外不存在目标的 dangling 软链),
//     一律拒绝(O_NOFOLLOW 语义)——否则 EvalSymlinks 对 dangling 目标走词法回退,
//     create/write 会跟随软链把文件写到 root 外。
//
// root 必须是已存在的绝对路径(调用方负责)。rel 为空或 "." 表示 root 本身。
func SafeJoin(root, rel string) (string, error) {
	root = filepath.Clean(root)
	// Clean 把 rel 当作绝对路径处理可去掉前导 "/",再相对 root 拼接,
	// 这样 rel="/etc/passwd" 会被当成 root 下的 "etc/passwd"。
	clean := filepath.Clean("/" + rel)
	candidate := filepath.Join(root, clean)

	if !withinRoot(root, candidate) {
		return "", ErrPathEscape
	}

	// 符号链接逃逸:解析候选路径中已存在的最长前缀的真实路径。
	resolved, err := resolveExisting(candidate)
	if err != nil {
		return "", err
	}
	if !withinRoot(root, resolved) {
		return "", ErrPathEscape
	}

	// 最终段若是符号链接(即便 dangling),写/创建会跟随它逃逸 root,直接拒绝。
	if candidate != root {
		if fi, err := os.Lstat(candidate); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return "", ErrPathEscape
		}
	}
	return candidate, nil
}

// withinRoot 判断 p 是否等于 root 或在 root 子树内(纯词法,要求二者均为 Clean 后的绝对路径)。
func withinRoot(root, p string) bool {
	if p == root {
		return true
	}
	prefix := root
	if prefix != string(filepath.Separator) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(p, prefix)
}

// resolveExisting 返回 p 的真实路径:沿父目录回退到已存在部分做 EvalSymlinks,
// 再把尚不存在的尾部拼回。这样对尚未创建的文件(如即将写入的新文件)也能校验其父目录不逃逸。
func resolveExisting(p string) (string, error) {
	missing := ""
	cur := p
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			if missing == "" {
				return resolved, nil
			}
			return filepath.Join(resolved, missing), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// 到达根仍不存在:返回词法清理结果,交给调用方的 withinRoot 判定。
			return filepath.Clean(p), nil
		}
		missing = filepath.Join(filepath.Base(cur), missing)
		cur = parent
	}
}
