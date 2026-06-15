package backup

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/MevYu/XPanel-Go/internal/system"
)

// 三个外部能力抽象为接口,便于 mock 测试:打包(tar.gz)、数据库转储、rclone 远端。

// archiver 把本地目录/文件打包成 tar.gz,以及解包还原。
type archiver interface {
	// archive 把 srcRoot 子树内的 rel(相对 srcRoot)打成 destFile(tar.gz),返回字节数。
	archive(srcRoot, rel, destFile string) (int64, error)
	// extract 把 srcFile(tar.gz)解到 destRoot 子树内(成员路径受 SafeJoin 约束)。
	extract(srcFile, destRoot string) error
}

// dumper 把数据库转储为单文件。
type dumper interface {
	dump(kind, dbName, destFile string, s Settings) (int64, error)
}

// rcloneRunner 封装 rclone CLI:配置远端、上传、列出、下载。
type rcloneRunner interface {
	available() error
	// configCreate 写入/更新一个 rclone remote(凭证经参数数组传入,不拼 shell)。
	configCreate(r Remote) error
	configDelete(name string) error
	// upload 把本地文件传到 remote:bucket 下。
	upload(localFile string, r Remote) error
	// list 列出 remote:bucket 下的文件名。
	list(r Remote) ([]string, error)
	// download 从 remote:bucket 取回 name 到 localFile。
	download(name, localFile string, r Remote) error
}

// --- 真实 tar.gz 实现 ---

type tarArchiver struct{}

// archive:把 srcRoot/rel 打成 destFile。rel 经 SafeJoin 限定在 srcRoot 内,
// 归档内成员路径相对 srcRoot,防止绝对路径/穿越写入 entry。
func (tarArchiver) archive(srcRoot, rel, destFile string) (int64, error) {
	src, err := system.SafeJoin(srcRoot, rel)
	if err != nil {
		return 0, err
	}
	f, err := os.Create(destFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	walkErr := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 软链不跟随(避免打包跟随软链逃出 srcRoot);记录为软链 entry。
		var link string
		if fi.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(srcRoot, p)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(name)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
	if walkErr != nil {
		tw.Close()
		gz.Close()
		return 0, walkErr
	}
	if err := tw.Close(); err != nil {
		return 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// errUnsafeEntry 表示 tar 成员路径试图逃出解包根目录。
var errUnsafeEntry = errors.New("tar entry escapes destination root")

// extract:解包到 destRoot,每个成员路径经 SafeJoin 限定(挡 ../ 与绝对路径 entry)。
func (tarArchiver) extract(srcFile, destRoot string) error {
	if err := os.MkdirAll(destRoot, 0o755); err != nil {
		return err
	}
	f, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		dest, err := system.SafeJoin(destRoot, hdr.Name)
		if err != nil {
			return errUnsafeEntry
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			// 限制单成员大小由调用方信任的归档保证;此处直接拷贝。
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		default:
			// 软链等类型在还原时跳过(避免软链逃逸);保守不还原。
		}
	}
	return nil
}
