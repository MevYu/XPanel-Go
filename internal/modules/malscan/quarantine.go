package malscan

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/MevYu/XPanel-Go/internal/system"
)

// quarantineFile 把 absPath(必须已在 scanRoot 内,调用方已 SafeJoin 校验)移动到
// quarantineDir。返回隔离区内的存储绝对路径。
//
// 优先 os.Rename(同设备原子移动);跨设备(EXDEV)回退到复制+删除。
// 文件名用随机前缀避免碰撞,保留原 basename 便于辨认。绝不执行被移动文件。
func quarantineFile(absPath, quarantineDir string) (string, error) {
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return "", err
	}
	tag, err := randTag()
	if err != nil {
		return "", err
	}
	// 在隔离区内用 SafeJoin 防 basename 含异常字符导致逃逸。
	dest, err := system.SafeJoin(quarantineDir, tag+"_"+filepath.Base(absPath))
	if err != nil {
		return "", err
	}
	if err := os.Rename(absPath, dest); err == nil {
		return dest, nil
	}
	// 跨设备等 Rename 失败:复制后删除源。
	if err := copyFile(absPath, dest); err != nil {
		return "", err
	}
	if err := os.Remove(absPath); err != nil {
		_ = os.Remove(dest) // 源删不掉则回滚目标,避免重复
		return "", err
	}
	return dest, nil
}

// restoreFile 把隔离区文件移回原路径。原路径已存在则不覆盖,返回错误。
func restoreFile(storedPath, origPath string) error {
	if _, err := os.Lstat(origPath); err == nil {
		return os.ErrExist
	}
	if err := os.MkdirAll(filepath.Dir(origPath), 0o755); err != nil {
		return err
	}
	if err := os.Rename(storedPath, origPath); err == nil {
		return nil
	}
	if err := copyFile(storedPath, origPath); err != nil {
		return err
	}
	return os.Remove(storedPath)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func randTag() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
