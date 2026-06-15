package migration

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/MevYu/XPanel-Go/internal/system"
)

// 迁移包(tar.gz)内部布局:
//
//	manifest.json   — Meta(域名/PHP 版本/库类型等)
//	site/<rel>      — 站点目录文件,路径相对站点根
//	database.sql    — 数据库转储(无库时不存在)
const (
	manifestName = "manifest.json"
	sitePrefix   = "site/"
	dbEntryName  = "database.sql"
)

// errUnsafeEntry 表示 tar 成员路径试图逃出解包根目录(tar slip)。
var errUnsafeEntry = errors.New("tar entry escapes destination root")

// errNoManifest 表示迁移包缺少 manifest,非本系统导出的合法包。
var errNoManifest = errors.New("migration package missing manifest")

// packer 把站点目录 + 可选数据库转储 + 元信息打成单个迁移包,以及反向解包。
// 抽象为接口便于 mock 测试导出/导入编排,与真实打包/解包逻辑解耦。
type packer interface {
	// pack 把 siteRoot 子树 + dbDump(可为空)+ meta 打成 destFile(tar.gz),返回字节数。
	pack(siteRoot, dbDump string, meta Meta, destFile string) (int64, error)
	// readManifest 只读出迁移包的 manifest,不解包文件(供导入前预览/校验)。
	readManifest(srcFile string) (Meta, error)
	// unpack 解包 srcFile:站点文件还原到 siteDest 子树,数据库转储(若有)写到 dbDumpDest。
	// 返回包内是否含数据库转储。成员路径一律经 SafeJoin 限定(tar slip 防护)。
	unpack(srcFile, siteDest, dbDumpDest string) (hasDB bool, err error)
}

type tarPacker struct{}

// pack 写顺序:manifest → site/* → database.sql。siteRoot 必须是已存在绝对目录;
// 软链不跟随(避免打包跟随软链逃出 siteRoot),记录为软链 entry。
func (tarPacker) pack(siteRoot, dbDump string, meta Meta, destFile string) (int64, error) {
	f, err := os.Create(destFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	if err := writeManifest(tw, meta); err != nil {
		closeWriters(tw, gz)
		return 0, err
	}
	if err := writeSiteTree(tw, siteRoot); err != nil {
		closeWriters(tw, gz)
		return 0, err
	}
	if dbDump != "" {
		if err := writeFileEntry(tw, dbDump, dbEntryName); err != nil {
			closeWriters(tw, gz)
			return 0, err
		}
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

func (tarPacker) readManifest(srcFile string) (Meta, error) {
	f, err := os.Open(srcFile)
	if err != nil {
		return Meta{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return Meta{}, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return Meta{}, errNoManifest
		}
		if err != nil {
			return Meta{}, err
		}
		if hdr.Name == manifestName {
			var meta Meta
			if err := json.NewDecoder(tr).Decode(&meta); err != nil {
				return Meta{}, err
			}
			return meta, nil
		}
	}
}

func (tarPacker) unpack(srcFile, siteDest, dbDumpDest string) (bool, error) {
	if err := os.MkdirAll(siteDest, 0o755); err != nil {
		return false, err
	}
	f, err := os.Open(srcFile)
	if err != nil {
		return false, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	hasDB := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return hasDB, err
		}
		switch {
		case hdr.Name == manifestName:
			// 元信息不落盘,导入流程另行 readManifest。
			continue
		case hdr.Name == dbEntryName:
			if dbDumpDest == "" {
				continue
			}
			if err := writeRegularTo(tr, dbDumpDest, 0o600); err != nil {
				return hasDB, err
			}
			hasDB = true
		case len(hdr.Name) > len(sitePrefix) && hdr.Name[:len(sitePrefix)] == sitePrefix:
			rel := hdr.Name[len(sitePrefix):]
			dest, err := system.SafeJoin(siteDest, rel)
			if err != nil {
				return hasDB, errUnsafeEntry
			}
			if err := extractMember(tr, hdr, dest); err != nil {
				return hasDB, err
			}
		default:
			// 非 site/ 前缀、非 database.sql 的成员不还原(只跳过)。
			// 仍过一遍 SafeJoin:仅当成员经符号链接真正逃出根时(中和后仍越界)拒绝。
			if _, err := system.SafeJoin(siteDest, hdr.Name); err != nil {
				return hasDB, errUnsafeEntry
			}
		}
	}
	return hasDB, nil
}

func extractMember(tr *tar.Reader, hdr *tar.Header, dest string) error {
	switch hdr.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(dest, os.FileMode(hdr.Mode))
	case tar.TypeReg:
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		return writeRegularTo(tr, dest, os.FileMode(hdr.Mode))
	default:
		// 软链等类型还原时跳过(避免软链逃逸),保守不还原。
		return nil
	}
}

func writeRegularTo(tr io.Reader, dest string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, tr); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func writeManifest(tw *tar.Writer, meta Meta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

// writeSiteTree 把 siteRoot 整棵子树写入 tw,成员名前缀 "site/" + 相对路径。
func writeSiteTree(tw *tar.Writer, siteRoot string) error {
	return filepath.Walk(siteRoot, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
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
		rel, err := filepath.Rel(siteRoot, p)
		if err != nil {
			return err
		}
		hdr.Name = sitePrefix + filepath.ToSlash(rel)
		if fi.IsDir() {
			hdr.Name += "/"
		}
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
}

// writeFileEntry 把单个本地文件 src 作为成员 name 写入 tw。
func writeFileEntry(tw *tar.Writer, src, name string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: fi.Size(), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = io.Copy(tw, in)
	return err
}

func closeWriters(tw *tar.Writer, gz *gzip.Writer) {
	tw.Close()
	gz.Close()
}
