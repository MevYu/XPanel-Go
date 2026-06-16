package sites

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Archiver 抽象站点目录的打包/解包/读取/删除,便于单测注入 mock。
// Unpack 实现必须拒绝任何越出 destDir 的条目(Zip-Slip)。
type Archiver interface {
	// Pack 把 srcDir 打成 tar.gz 写入 destPath(均为绝对路径),返回归档字节数。
	Pack(srcDir, destPath string) (int64, error)
	// Unpack 解开 archivePath 到 destDir。必须拒绝任何 cleaned 后逃出 destDir 的条目
	// (".."、绝对路径、指向外部的软链)。
	Unpack(archivePath, destDir string) error
	// Open 返回归档的只读流供下载。调用方负责 Close。
	Open(archivePath string) (io.ReadCloser, error)
	// Remove 删除归档文件(不存在视为成功)。
	Remove(archivePath string) error
}

// 防解压炸弹:限制解压后的总字节数与文件数。
const (
	maxUnpackBytes = 2 << 30 // 2 GiB
	maxUnpackFiles = 100000
)

// backupFileRe 约束服务端生成的归档文件名:无斜杠、无 ..、固定 .tar.gz 后缀。
var backupFileRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}\.tar\.gz$`)

// backupPath 校验 filename 并拼出 BackupDir 下的绝对路径,二次校验防穿越。
func backupPath(set Settings, filename string) (string, error) {
	if !backupFileRe.MatchString(filename) || strings.Contains(filename, "..") {
		return "", fmt.Errorf("invalid backup filename")
	}
	p := filepath.Join(set.BackupDir, filename)
	if filepath.Dir(p) != filepath.Clean(set.BackupDir) {
		return "", fmt.Errorf("backup path escapes backup dir")
	}
	return p, nil
}

// realArchiver 用 archive/tar + compress/gzip 实现。
type realArchiver struct{}

func (*realArchiver) Pack(srcDir, destPath string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return 0, err
	}
	f, err := os.Create(destPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	walkErr := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 跳过软链:避免归档泄漏 srcDir 之外的内容。
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		return err
	})
	if walkErr != nil {
		tw.Close()
		gw.Close()
		return 0, walkErr
	}
	if err := tw.Close(); err != nil {
		gw.Close()
		return 0, err
	}
	if err := gw.Close(); err != nil {
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	fi, err := os.Stat(destPath)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func (*realArchiver) Unpack(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)

	cleanDest := filepath.Clean(destDir)
	prefix := cleanDest + string(os.PathSeparator)
	var total int64
	var count int

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// 软链/硬链一律拒绝:可指向 destDir 外。
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			return fmt.Errorf("backup: link entry %q rejected", hdr.Name)
		}
		if strings.Contains(hdr.Name, "..") || filepath.IsAbs(hdr.Name) || strings.HasPrefix(hdr.Name, "/") {
			return fmt.Errorf("backup: unsafe entry name %q", hdr.Name)
		}
		target := filepath.Join(cleanDest, filepath.Clean("/"+hdr.Name))
		cleanTarget := filepath.Clean(target)
		if cleanTarget != cleanDest && !strings.HasPrefix(cleanTarget, prefix) {
			return fmt.Errorf("backup: entry %q escapes destination", hdr.Name)
		}
		count++
		if count > maxUnpackFiles {
			return fmt.Errorf("backup: too many entries (>%d)", maxUnpackFiles)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(cleanTarget, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(cleanTarget), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(cleanTarget, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			n, err := io.CopyN(out, tr, maxUnpackBytes-total+1)
			out.Close()
			if err != nil && err != io.EOF {
				return err
			}
			total += n
			if total > maxUnpackBytes {
				return fmt.Errorf("backup: archive too large (>%d bytes)", maxUnpackBytes)
			}
		default:
			// 忽略其它条目类型(设备/FIFO 等)。
		}
	}
	return nil
}

func (*realArchiver) Open(archivePath string) (io.ReadCloser, error) {
	return os.Open(archivePath)
}

func (*realArchiver) Remove(archivePath string) error {
	return removeIfExists(archivePath)
}
