// Package files 实现面板内文件管理与外链分享模块。
//
// 两个权限平面严格隔离:
//   - 面板平面(Routes):挂 /api/m/files/,走面板认证 + RBAC + 审计,可读写。
//     所有路径限定在 panel root 内(SafeJoin)。
//   - 公开平面(PublicRoutes):挂 /s/<token>,无面板认证,只读,
//     访问范围独立限定在被分享路径的子树内(再做一层 SafeJoin)。
package files

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Deps 注入宿主能力,避免直接耦合 server 包。与 service 模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string)
	Audit     func(userID *int64, action, detail, ip string)
	ClientIP  func(*http.Request) string // 取真实客户端 IP(受信代理感知)
}

// Module 是文件管理 + 外链分享模块。
type Module struct {
	root   string // 面板文件根的绝对路径,所有面板操作限定其内
	deps   Deps
	shares *shareStore
	pubLim *rateLimiter // 公开端点独立限速
}

// New 构造模块。root 为面板文件根(绝对路径);st 用于自管分享表。
// root 为空时回退到环境变量 XPANEL_FILES_ROOT,再回退到 "/".
func New(root string, st *store.Store, deps Deps) (*Module, error) {
	if root == "" {
		root = os.Getenv("XPANEL_FILES_ROOT")
	}
	if root == "" {
		root = "/"
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	ss, err := newShareStore(st)
	if err != nil {
		return nil, err
	}
	return &Module{
		root:   filepath.Clean(abs),
		deps:   deps,
		shares: ss,
		pubLim: newRateLimiter(20), // 公开端点更严:每 IP 20 burst
	}, nil
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "files", Name: "文件管理", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "文件管理", Icon: "folder", Path: "/files"}}
}

func (*Module) Start(module.Context) error { return nil }
func (*Module) Stop(module.Context) error  { return nil }

// HealthCheck:根目录必须存在且为目录。
func (m *Module) HealthCheck() error {
	fi, err := os.Stat(m.root)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("files root is not a directory")
	}
	return nil
}

func (m *Module) Routes(r module.Router) {
	// 只读:任意已认证角色
	r.Get("/list", m.handleList)
	r.Get("/read", m.handleRead)
	r.Get("/download", m.handleDownload)

	// 写:需 operator/admin
	r.Post("/write", m.requireWrite(m.handleWrite))
	r.Post("/upload", m.requireWrite(m.handleUpload))
	r.Post("/mkdir", m.requireWrite(m.handleMkdir))
	r.Post("/rename", m.requireWrite(m.handleRename))
	r.Post("/copy", m.requireWrite(m.handleCopy))
	r.Post("/delete", m.requireWrite(m.handleDelete))
	r.Post("/chmod", m.requireWrite(m.handleChmod))
	r.Post("/compress", m.requireWrite(m.handleCompress))
	r.Post("/extract", m.requireWrite(m.handleExtract))

	// 分享管理:创建/列出/撤销(创建需 operator/admin,列/撤销仅创建者或 admin)
	r.Post("/shares", m.requireWrite(m.handleShareCreate))
	r.Get("/shares", m.handleShareList)
	r.Delete("/shares/{token}", m.handleShareRevoke)
}

// requireWrite 包一层 RBAC:仅 operator/admin 可进。
func (m *Module) requireWrite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, role := m.deps.Principal(r)
		if role != "admin" && role != "operator" {
			http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// resolve 把请求里的相对路径限定在面板根内。
func (m *Module) resolve(rel string) (string, error) {
	return system.SafeJoin(m.root, rel)
}

func (m *Module) audit(r *http.Request, action, detail string) {
	uid, _ := m.deps.Principal(r)
	m.deps.Audit(&uid, action, detail, m.clientIP(r))
}

// ---- 只读操作 ----

type dirEntry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime int64  `json:"mod_time"`
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) {
	abs, err := m.resolve(r.URL.Query().Get("path"))
	if err != nil {
		pathError(w, err)
		return
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		fsError(w, err)
		return
	}
	out := make([]dirEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, dirEntry{
			Name: e.Name(), IsDir: e.IsDir(), Size: info.Size(),
			Mode: info.Mode().String(), ModTime: info.ModTime().Unix(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) handleRead(w http.ResponseWriter, r *http.Request) {
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
	if fi.IsDir() {
		http.Error(w, "is a directory", http.StatusBadRequest)
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		fsError(w, err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, f)
}

func (m *Module) handleDownload(w http.ResponseWriter, r *http.Request) {
	abs, err := m.resolve(r.URL.Query().Get("path"))
	if err != nil {
		pathError(w, err)
		return
	}
	serveFileDownload(w, abs)
}

// ---- 写操作 ----

func (m *Module) handleWrite(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	abs, err := m.resolve(rel)
	if err != nil {
		pathError(w, err)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<20)) // 64 MiB 上限
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.write", rel)
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleUpload(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("path")
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "parse form failed", http.StatusBadRequest)
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	// 文件名只取 base,防目录穿越;再整体经 SafeJoin。
	abs, err := m.resolve(filepath.Join(dir, filepath.Base(hdr.Filename)))
	if err != nil {
		pathError(w, err)
		return
	}
	dst, err := os.OpenFile(abs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		fsError(w, err)
		return
	}
	defer dst.Close()
	if _, err := io.Copy(dst, file); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.upload", filepath.Join(dir, filepath.Base(hdr.Filename)))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleMkdir(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	abs, err := m.resolve(rel)
	if err != nil {
		pathError(w, err)
		return
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.mkdir", rel)
	w.WriteHeader(http.StatusNoContent)
}

type renameReq struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func (m *Module) handleRename(w http.ResponseWriter, r *http.Request) {
	var req renameReq
	if !decodeJSON(w, r, &req) {
		return
	}
	from, err := m.resolve(req.From)
	if err != nil {
		pathError(w, err)
		return
	}
	to, err := m.resolve(req.To)
	if err != nil {
		pathError(w, err)
		return
	}
	if err := os.Rename(from, to); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.rename", req.From+" -> "+req.To)
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleCopy(w http.ResponseWriter, r *http.Request) {
	var req renameReq
	if !decodeJSON(w, r, &req) {
		return
	}
	from, err := m.resolve(req.From)
	if err != nil {
		pathError(w, err)
		return
	}
	to, err := m.resolve(req.To)
	if err != nil {
		pathError(w, err)
		return
	}
	if err := copyPath(from, to); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.copy", req.From+" -> "+req.To)
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
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
	if err := os.RemoveAll(abs); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.delete", rel)
	w.WriteHeader(http.StatusNoContent)
}

type chmodReq struct {
	Path string `json:"path"`
	Mode string `json:"mode"` // 八进制字符串,如 "0644"
}

func (m *Module) handleChmod(w http.ResponseWriter, r *http.Request) {
	var req chmodReq
	if !decodeJSON(w, r, &req) {
		return
	}
	abs, err := m.resolve(req.Path)
	if err != nil {
		pathError(w, err)
		return
	}
	mode, err := strconv.ParseUint(req.Mode, 8, 32)
	if err != nil {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}
	if err := os.Chmod(abs, os.FileMode(mode)); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.chmod", req.Path+" "+req.Mode)
	w.WriteHeader(http.StatusNoContent)
}

type compressReq struct {
	Paths []string `json:"paths"` // 待压缩条目(相对根)
	Dest  string   `json:"dest"`  // 目标 zip(相对根)
}

func (m *Module) handleCompress(w http.ResponseWriter, r *http.Request) {
	var req compressReq
	if !decodeJSON(w, r, &req) {
		return
	}
	dest, err := m.resolve(req.Dest)
	if err != nil {
		pathError(w, err)
		return
	}
	srcs := make([]string, 0, len(req.Paths))
	for _, p := range req.Paths {
		abs, err := m.resolve(p)
		if err != nil {
			pathError(w, err)
			return
		}
		srcs = append(srcs, abs)
	}
	if err := zipPaths(dest, srcs); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.compress", req.Dest)
	w.WriteHeader(http.StatusNoContent)
}

type extractReq struct {
	Path string `json:"path"` // 源 zip(相对根)
	Dest string `json:"dest"` // 解压目录(相对根)
}

func (m *Module) handleExtract(w http.ResponseWriter, r *http.Request) {
	var req extractReq
	if !decodeJSON(w, r, &req) {
		return
	}
	src, err := m.resolve(req.Path)
	if err != nil {
		pathError(w, err)
		return
	}
	destRoot, err := m.resolve(req.Dest)
	if err != nil {
		pathError(w, err)
		return
	}
	// 解压时每个条目再经 SafeJoin(destRoot, name),挡 zip-slip。
	if err := unzip(src, destRoot); err != nil {
		fsError(w, err)
		return
	}
	m.audit(r, "files.extract", req.Path+" -> "+req.Dest)
	w.WriteHeader(http.StatusNoContent)
}

// ---- 分享管理 ----

type shareCreateReq struct {
	Path         string `json:"path"`
	Password     string `json:"password"`       // 可选
	AllowList    bool   `json:"allow_list"`     // 是否允许列目录
	ExpiresInSec int64  `json:"expires_in_sec"` // 0 表示永不过期
	MaxDownloads int64  `json:"max_downloads"`  // 0 表示不限
}

type shareResp struct {
	Token        string `json:"token"`
	Path         string `json:"path"`
	HasPassword  bool   `json:"has_password"`
	AllowList    bool   `json:"allow_list"`
	ExpiresAt    int64  `json:"expires_at"`
	MaxDownloads int64  `json:"max_downloads"`
	Downloads    int64  `json:"downloads"`
	CreatedAt    int64  `json:"created_at"`
}

func (m *Module) handleShareCreate(w http.ResponseWriter, r *http.Request) {
	var req shareCreateReq
	if !decodeJSON(w, r, &req) {
		return
	}
	// 校验路径在面板根内且存在。
	abs, err := m.resolve(req.Path)
	if err != nil {
		pathError(w, err)
		return
	}
	if _, err := os.Stat(abs); err != nil {
		fsError(w, err)
		return
	}
	uid, _ := m.deps.Principal(r)
	sh := Share{
		RelPath:      normalizeRel(req.Path),
		OwnerID:      uid,
		AllowList:    req.AllowList,
		MaxDownloads: req.MaxDownloads,
	}
	if req.ExpiresInSec > 0 {
		sh.ExpiresAt = nowUnix() + req.ExpiresInSec
	}
	if req.Password != "" {
		h, err := auth.HashPassword(req.Password)
		if err != nil {
			http.Error(w, "hash failed", http.StatusInternalServerError)
			return
		}
		sh.PassHash = h
	}
	tok, err := m.shares.create(sh)
	if err != nil {
		http.Error(w, "create share failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "files.share.create", req.Path+" token="+tok, m.clientIP(r))
	writeJSON(w, http.StatusCreated, toShareResp(sh, tok))
}

func (m *Module) handleShareList(w http.ResponseWriter, r *http.Request) {
	uid, _ := m.deps.Principal(r)
	shares, err := m.shares.listByOwner(uid)
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	out := make([]shareResp, 0, len(shares))
	for _, sh := range shares {
		out = append(out, toShareResp(sh, sh.Token))
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) handleShareRevoke(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	uid, role := m.deps.Principal(r)
	ok, err := m.shares.revoke(token, uid, role == "admin")
	if err != nil {
		http.Error(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	m.deps.Audit(&uid, "files.share.revoke", "token="+token, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func toShareResp(sh Share, tok string) shareResp {
	return shareResp{
		Token: tok, Path: sh.RelPath, HasPassword: sh.PassHash != "",
		AllowList: sh.AllowList, ExpiresAt: sh.ExpiresAt,
		MaxDownloads: sh.MaxDownloads, Downloads: sh.Downloads, CreatedAt: sh.CreatedAt,
	}
}

// normalizeRel 把分享路径规范成相对根的干净形式(去掉前导 /,中和 ..)。
func normalizeRel(rel string) string {
	clean := filepath.Clean("/" + rel)
	return strings.TrimPrefix(clean, "/")
}

// ---- 共享辅助 ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return false
	}
	return true
}

// pathError 把路径逃逸统一成 403(不泄露根布局)。
func pathError(w http.ResponseWriter, err error) {
	if errors.Is(err, system.ErrPathEscape) {
		http.Error(w, "forbidden: path escapes root", http.StatusForbidden)
		return
	}
	http.Error(w, "invalid path", http.StatusBadRequest)
}

// fsError 把文件系统错误映射成不泄露细节的状态码。
func fsError(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if errors.Is(err, os.ErrPermission) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}
	http.Error(w, "filesystem error", http.StatusInternalServerError)
}

// clientIP 取真实客户端 IP:有受信代理感知的提取器则用之,否则回退 RemoteAddr。
func (m *Module) clientIP(r *http.Request) string {
	if m.deps.ClientIP != nil {
		return m.deps.ClientIP(r)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// serveFileDownload 以 attachment 形式发送单个文件。
func serveFileDownload(w http.ResponseWriter, abs string) {
	fi, err := os.Stat(abs)
	if err != nil {
		fsError(w, err)
		return
	}
	if fi.IsDir() {
		http.Error(w, "is a directory", http.StatusBadRequest)
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		fsError(w, err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(abs)+"\"")
	_, _ = io.Copy(w, f)
}

// copyPath 递归复制文件或目录。
func copyPath(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return copyDir(src, dst, fi.Mode())
	}
	return copyFile(src, dst, fi.Mode())
}

func copyDir(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(dst, mode.Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if err := copyPath(s, d); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// zipPaths 把 srcs 打包成 dest(zip)。条目名用各自的 base。
func zipPaths(dest string, srcs []string) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	defer zw.Close()
	for _, src := range srcs {
		base := filepath.Base(src)
		if err := addToZip(zw, src, base); err != nil {
			return err
		}
	}
	return nil
}

func addToZip(zw *zip.Writer, src, name string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := addToZip(zw, filepath.Join(src, e.Name()), name+"/"+e.Name()); err != nil {
				return err
			}
		}
		return nil
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	wr, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(wr, f)
	return err
}

// unzip 解压 src 到 destRoot;每个条目经 SafeJoin 校验,挡 zip-slip。
func unzip(src, destRoot string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	if err := os.MkdirAll(destRoot, 0o755); err != nil {
		return err
	}
	for _, f := range zr.File {
		target, err := system.SafeJoin(destRoot, f.Name)
		if err != nil {
			return err // zip-slip 被拒
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := extractZipFile(f, target); err != nil {
			return err
		}
	}
	return nil
}

func extractZipFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc) //nolint:gosec // 条目已经过 SafeJoin 限定
	return err
}
