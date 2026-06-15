package files

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// PublicPrefix 把外链端点挂在 /s 下,面板 RequireAuth 之外。
func (*Module) PublicPrefix() string { return "/s" }

// PublicRoutes 返回公开外链端点(集成挂在 /s/ 下,面板 RequireAuth 之外)。
//
// 权限平面与面板完全隔离:
//   - 不解析任何面板 JWT/会话;token 即唯一凭据。
//   - 严格只读;访问范围独立限定在分享路径子树内(以分享根再做一层 SafeJoin)。
//   - 独立(更严)限速 + 独立审计。
//
// 路由形态:
//   - GET /{token}            分享根(单文件直下;目录:允许列目录则返回 JSON,否则 403)
//   - GET /{token}/*          分享根下的子路径
func (m *Module) PublicRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(m.pubLim.middleware)
	r.Get("/{token}", m.handlePublic)
	r.Get("/{token}/*", m.handlePublic)
	return r
}

func (m *Module) handlePublic(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	sub := chi.URLParam(r, "*") // 分享根内的子路径,可能为空

	sh, err := m.shares.get(token)
	if err != nil {
		// 不存在的 token 与撤销的 token 一致返回 404,不区分。
		http.NotFound(w, r)
		return
	}

	// 过期:410 Gone。
	if sh.ExpiresAt != 0 && nowUnix() >= sh.ExpiresAt {
		m.auditPublic(r, "files.public.expired", token, "")
		http.Error(w, "share expired", http.StatusGone)
		return
	}

	// 访问密码:校验 hash。密码经 ?pw= 或 X-Share-Password 头传入。
	if sh.PassHash != "" {
		pw := r.URL.Query().Get("pw")
		if pw == "" {
			pw = r.Header.Get("X-Share-Password")
		}
		if !auth.VerifyPassword(sh.PassHash, pw) {
			m.auditPublic(r, "files.public.denied", token, "bad password")
			http.Error(w, "password required", http.StatusUnauthorized)
			return
		}
	}

	// 分享根:面板根内的分享路径,作为公开访问的独立新根。
	shareRoot, err := system.SafeJoin(m.root, sh.RelPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rootInfo, err := os.Stat(shareRoot)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// 子路径独立再做一层限定:任何 ../、软链、绝对路径都逃不出 shareRoot。
	target, err := system.SafeJoin(shareRoot, sub)
	if err != nil {
		m.auditPublic(r, "files.public.escape", token, sub)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	info, err := os.Stat(target)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if info.IsDir() {
		m.servePublicDir(w, r, sh, shareRoot, target, rootInfo)
		return
	}
	m.servePublicFile(w, r, sh, token, target)
}

// servePublicDir 处理目录:未开启列目录则 403;开启则返回该目录条目 JSON。
func (m *Module) servePublicDir(w http.ResponseWriter, r *http.Request, sh Share, shareRoot, target string, rootInfo os.FileInfo) {
	if !sh.AllowList {
		// 分享根本身是单文件时不会进这里;此处即"目录但禁列目录"。
		http.Error(w, "directory listing disabled", http.StatusForbidden)
		return
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	out := make([]dirEntry, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, dirEntry{
			Name: e.Name(), IsDir: e.IsDir(), Size: fi.Size(),
			Mode: fi.Mode().String(), ModTime: fi.ModTime().Unix(),
		})
	}
	_ = rootInfo
	m.auditPublic(r, "files.public.list", sh.Token, strings.TrimPrefix(target, shareRoot))
	writeJSON(w, http.StatusOK, out)
}

// servePublicFile 下载单文件:先原子地检查并自增下载计数(挡超限竞争),再发送。
func (m *Module) servePublicFile(w http.ResponseWriter, r *http.Request, sh Share, token, target string) {
	if sh.MaxDownloads > 0 {
		ok, err := m.shares.incDownloadIfAllowed(token)
		if err != nil {
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		if !ok {
			m.auditPublic(r, "files.public.limit", token, "")
			http.Error(w, "download limit reached", http.StatusGone)
			return
		}
	}
	m.auditPublic(r, "files.public.download", token, filepath.Base(target))
	servePublicDownload(w, target)
}

// servePublicDownload 与面板下载共享逻辑,但严格只读,无目录分支泄露。
func servePublicDownload(w http.ResponseWriter, abs string) {
	f, err := os.Open(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(abs)+"\"")
	_, _ = io.Copy(w, f)
}

// auditPublic 写公开端点独立审计(token / 访问者 IP / 命中)。userID 恒为 nil:公开访问无登录主体。
func (m *Module) auditPublic(r *http.Request, action, token, detail string) {
	d := "token=" + token
	if detail != "" {
		d += " " + detail
	}
	m.deps.Audit(nil, action, d, clientIP(r))
}

func nowUnix() int64 { return time.Now().Unix() }
