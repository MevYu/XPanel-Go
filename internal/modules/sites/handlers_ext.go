package sites

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// 各站点设置子端点。写入(PUT/POST/DELETE)统一 operator+,经 applySite 重生成→nginx -t→reload。
// 输入严格白名单校验,非法即 400,绝不进配置。

// loadForWrite 校验写权限 + 取站点,失败已写响应。
func (m *Module) loadForWrite(w http.ResponseWriter, r *http.Request) (Site, bool) {
	if _, ok := m.requireWriter(w, r); !ok {
		return Site{}, false
	}
	return m.loadSite(w, r)
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

// --- domains ---

func (m *Module) handlePutDomains(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		Bindings []Domain `json:"bindings"`
		Domains  []string `json:"domains"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	bindings, err := buildBindings(createRequest{Bindings: req.Bindings, Domains: req.Domains, Listen: site.Listen})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	site.DomainBindings = bindings
	site.Domains = domainsOf(bindings)
	m.applySite(w, r, site, "sites.domains.update", site.Name)
}

// --- php version ---

func (m *Module) handleGetPHP(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"php_version": site.PHPVersion})
}

func (m *Module) handlePutPHP(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	if site.Kind != string(KindPHP) {
		http.Error(w, "site is not a PHP site", http.StatusConflict)
		return
	}
	var req struct {
		PHPVersion string `json:"php_version"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.PHPVersion != "" && !validPHPVersion(req.PHPVersion) {
		http.Error(w, "invalid php version", http.StatusBadRequest)
		return
	}
	site.PHPVersion = req.PHPVersion
	m.applySite(w, r, site, "sites.php.update", site.Name+" -> "+req.PHPVersion)
}

// --- rewrite ---

func (m *Module) handleRewriteTemplates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, listRewriteTemplates())
}

func (m *Module) handleGetRewrite(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"rewrite_rules": site.RewriteRules})
}

func (m *Module) handlePutRewrite(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		RewriteRules string `json:"rewrite_rules"`
		Template     string `json:"template"` // 可选:用内置模板 id 填充
	}
	if !decodeBody(w, r, &req) {
		return
	}
	rules := req.RewriteRules
	if req.Template != "" {
		tpl, found := findRewriteTemplate(req.Template)
		if !found {
			http.Error(w, "unknown rewrite template", http.StatusBadRequest)
			return
		}
		rules = tpl.Content
	}
	if err := validNginxFragment(rules); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	site.RewriteRules = rules
	m.applySite(w, r, site, "sites.rewrite.update", site.Name)
}

// --- proxy ---

func (m *Module) handleGetProxy(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"proxy_target": site.ProxyTarget})
}

func (m *Module) handlePutProxy(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	if site.Kind != string(KindProxy) {
		http.Error(w, "site is not a proxy site", http.StatusConflict)
		return
	}
	var req struct {
		ProxyTarget string        `json:"proxy_target"`
		Upstreams   []string      `json:"upstreams"`
		Cache       bool          `json:"cache"`
		CacheTime   int           `json:"cache_time"`
		SetHeaders  []ProxyHeader `json:"set_headers"`
		WebSocket   bool          `json:"websocket"`
		SendHost    string        `json:"send_host"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	pc := ProxyConfig{Cache: req.Cache, CacheTime: req.CacheTime, WebSocket: req.WebSocket, SendHost: req.SendHost}

	// 上游:优先多上游列表,否则单 proxy_target。两者其一必填。
	if len(req.Upstreams) > 0 {
		if len(req.Upstreams) > 32 {
			http.Error(w, "too many upstreams (max 32)", http.StatusBadRequest)
			return
		}
		ups := make([]string, 0, len(req.Upstreams))
		for _, raw := range req.Upstreams {
			up, err := validUpstream(raw)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			ups = append(ups, up)
		}
		pc.Upstreams = ups
		site.ProxyTarget = ups[0]
	} else {
		up, err := validUpstream(req.ProxyTarget)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		site.ProxyTarget = up
	}

	if pc.Cache && (pc.CacheTime < 1 || pc.CacheTime > 2592000) {
		http.Error(w, "cache_time must be 1..2592000 seconds", http.StatusBadRequest)
		return
	}
	if len(req.SetHeaders) > 32 {
		http.Error(w, "too many headers (max 32)", http.StatusBadRequest)
		return
	}
	for _, h := range req.SetHeaders {
		if !validProxyHeaderName(h.Name) {
			http.Error(w, "invalid header name "+h.Name, http.StatusBadRequest)
			return
		}
		if err := validProxyHeaderValue(h.Value); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	pc.SetHeaders = req.SetHeaders
	if !validSendHost(pc.SendHost) {
		http.Error(w, "invalid send_host", http.StatusBadRequest)
		return
	}

	site.Proxy = pc
	m.applySite(w, r, site, "sites.proxy.update", site.Name+" -> "+site.ProxyTarget)
}

// --- limits ---

func (m *Module) handlePutLimits(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		RateKB int `json:"rate_kb"`
		Conn   int `json:"conn"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.RateKB < 0 || req.RateKB > 1048576 {
		http.Error(w, "rate_kb must be 0..1048576", http.StatusBadRequest)
		return
	}
	if req.Conn < 0 || req.Conn > 65535 {
		http.Error(w, "conn must be 0..65535", http.StatusBadRequest)
		return
	}
	site.Limits = Limits{RateKB: req.RateKB, Conn: req.Conn}
	m.applySite(w, r, site, "sites.limits.update", site.Name)
}

// --- default docs ---

func (m *Module) handleGetDefaultDocs(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"index_docs": site.IndexDocs})
}

func (m *Module) handlePutDefaultDocs(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		IndexDocs []string `json:"index_docs"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := validIndexDocs(req.IndexDocs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	site.IndexDocs = req.IndexDocs
	m.applySite(w, r, site, "sites.docs.update", site.Name)
}

// --- dir protect ---

func (m *Module) handleGetDirProtect(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	// 不回显口令哈希。
	out := make([]map[string]string, 0, len(site.DirProtect))
	for _, d := range site.DirProtect {
		out = append(out, map[string]string{"path": d.Path, "username": d.Username})
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) handleAddDirProtect(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		Path     string `json:"path"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := validLocationPath(req.Path); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !validBasicUsername(req.Username) {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}
	if req.Password == "" || len(req.Password) > 256 {
		http.Error(w, "invalid password", http.StatusBadRequest)
		return
	}
	hash, err := m.hasher.Hash(req.Password)
	if err != nil {
		http.Error(w, "hash failed", http.StatusInternalServerError)
		return
	}
	// 同 path+user 覆盖;否则追加。
	dp := DirProtect{Path: req.Path, Username: req.Username, PassHash: hash}
	replaced := false
	for i, e := range site.DirProtect {
		if e.Path == dp.Path && e.Username == dp.Username {
			site.DirProtect[i] = dp
			replaced = true
			break
		}
	}
	if !replaced {
		site.DirProtect = append(site.DirProtect, dp)
	}
	m.applySite(w, r, site, "sites.dirprotect.add", site.Name+" "+req.Path)
}

func (m *Module) handleDeleteDirProtect(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		Path     string `json:"path"`
		Username string `json:"username"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	kept := site.DirProtect[:0:0]
	for _, e := range site.DirProtect {
		if e.Path == req.Path && (req.Username == "" || e.Username == req.Username) {
			continue
		}
		kept = append(kept, e)
	}
	site.DirProtect = kept
	m.applySite(w, r, site, "sites.dirprotect.delete", site.Name+" "+req.Path)
}

// --- redirects ---

func (m *Module) handleGetRedirects(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	if site.Redirects == nil {
		site.Redirects = []Redirect{}
	}
	writeJSON(w, http.StatusOK, site.Redirects)
}

func (m *Module) handlePutRedirects(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		Redirects []Redirect `json:"redirects"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Redirects) > 64 {
		http.Error(w, "too many redirects", http.StatusBadRequest)
		return
	}
	for _, rd := range req.Redirects {
		if err := validLocationPath(rd.From); err != nil {
			http.Error(w, "redirect from: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := validRedirectTarget(rd.To); err != nil {
			http.Error(w, "redirect to: "+err.Error(), http.StatusBadRequest)
			return
		}
		if !validRedirectCode(rd.Code) {
			http.Error(w, "redirect code must be 301 or 302", http.StatusBadRequest)
			return
		}
	}
	site.Redirects = req.Redirects
	m.applySite(w, r, site, "sites.redirects.update", site.Name)
}

// --- anti-leech ---

func (m *Module) handleGetAntiLeech(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, site.AntiLeech)
}

func (m *Module) handlePutAntiLeech(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var al AntiLeech
	if !decodeBody(w, r, &al) {
		return
	}
	if al.Enabled {
		if len(al.Extensions) == 0 || len(al.Extensions) > 64 {
			http.Error(w, "anti-leech requires 1..64 extensions", http.StatusBadRequest)
			return
		}
		for _, e := range al.Extensions {
			if !validExtension(e) {
				http.Error(w, "invalid extension "+e, http.StatusBadRequest)
				return
			}
		}
		for i, ref := range al.AllowedReferers {
			al.AllowedReferers[i] = strings.ToLower(strings.TrimSpace(ref))
			if !validReferer(al.AllowedReferers[i]) {
				http.Error(w, "invalid referer "+ref, http.StatusBadRequest)
				return
			}
		}
	}
	site.AntiLeech = al
	m.applySite(w, r, site, "sites.antileech.update", site.Name)
}

// --- ssl ---

func (m *Module) handleGetSSL(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, site.SSL)
}

func (m *Module) handlePutSSL(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		Enabled    bool   `json:"ssl_enabled"`
		ForceHTTPS bool   `json:"force_https"`
		HSTS       bool   `json:"hsts"`
		CertPath   string `json:"cert_path"`
		KeyPath    string `json:"key_path"`
		CertPEM    string `json:"cert_pem"` // 可选:直接上传证书内容,写盘后引用
		KeyPEM     string `json:"key_pem"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	ssl := SSL{Enabled: req.Enabled, ForceHTTPS: req.ForceHTTPS, HSTS: req.HSTS, CertPath: req.CertPath, KeyPath: req.KeyPath}
	if req.Enabled {
		set, ok := m.loadSettings(w)
		if !ok {
			return
		}
		ng := m.newNginx(set.ConfDir)
		// 上传 PEM:写到 confDir/ssl/<name>/,并取其路径。
		if req.CertPEM != "" || req.KeyPEM != "" {
			cp, kp, err := writeCertPair(ng, set, site.Name, req.CertPEM, req.KeyPEM)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			ssl.CertPath, ssl.KeyPath = cp, kp
		}
		if err := validCertPath(ssl.CertPath); err != nil {
			http.Error(w, "cert_path: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := validCertPath(ssl.KeyPath); err != nil {
			http.Error(w, "key_path: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	site.SSL = ssl
	m.applySite(w, r, site, "sites.ssl.update", site.Name)
}

// --- logs ---

func (m *Module) handleLogs(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	logType := r.URL.Query().Get("type")
	path := site.AccessLog
	if logType == "error" {
		path = site.ErrorLog
	}
	tail := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("tail")); err == nil && n > 0 && n <= 5000 {
		tail = n
	}
	set, ok := m.loadSettings(w)
	if !ok {
		return
	}
	ng := m.newNginx(set.ConfDir)
	content, err := ng.ReadLog(path, tail)
	if err != nil {
		http.Error(w, "log read failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"type": orDefault(logType, "access"), "tail": tail, "content": content})
}

// handlePutErrorPages 设置自定义错误页。
func (m *Module) handlePutErrorPages(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		ErrorPages []ErrorPage `json:"error_pages"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.ErrorPages) > 16 {
		http.Error(w, "too many error pages (max 16)", http.StatusBadRequest)
		return
	}
	for _, ep := range req.ErrorPages {
		if !validErrorPageCode(ep.Code) {
			http.Error(w, "invalid error page code", http.StatusBadRequest)
			return
		}
		if err := validLocationPath(ep.Path); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	site.ErrorPages = req.ErrorPages
	m.applySite(w, r, site, "sites.errorpages.update", site.Name)
}

// handlePutLogConfig 开关站点访问日志。
func (m *Module) handlePutLogConfig(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	site.LogEnabled = req.Enabled
	m.applySite(w, r, site, "sites.logs.config", site.Name)
}

// handleLogDownload 流式下载站点的 access/error 日志。路径取自持久化字段,绝不接受用户路径。
func (m *Module) handleLogDownload(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	kind := chi.URLParamFromCtx(r.Context(), "kind")
	path := site.AccessLog
	if kind == "error" {
		path = site.ErrorLog
	}
	set, ok := m.loadSettings(w)
	if !ok {
		return
	}
	ng := m.newNginx(set.ConfDir)
	rc, err := ng.OpenLog(path)
	if err != nil {
		http.Error(w, "log open failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+site.Name+"."+kind+`.log"`)
	w.WriteHeader(http.StatusOK)
	if rc == nil {
		return
	}
	defer rc.Close()
	_, _ = io.Copy(w, rc)
}

// handlePutRoot 设置站点根为 web 根下的绝对路径(区别于 run-dir 的相对子目录)。
func (m *Module) handlePutRoot(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	if site.Kind == string(KindProxy) {
		http.Error(w, "proxy site has no root dir", http.StatusConflict)
		return
	}
	var req struct {
		RootDir string `json:"root_dir"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	set, ok := m.loadSettings(w)
	if !ok {
		return
	}
	root, err := safeAbsUnder(set.WebRoot, req.RootDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	site.RootDir = root
	m.applySite(w, r, site, "sites.root.update", site.Name+" -> "+root)
}

// --- run dir ---

func (m *Module) handleGetRunDir(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"run_dir": site.RootDir})
}

func (m *Module) handlePutRunDir(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	if site.Kind == string(KindProxy) {
		http.Error(w, "proxy site has no run dir", http.StatusConflict)
		return
	}
	var req struct {
		Subdir string `json:"subdir"` // 站点根下的子目录,如 "public"
	}
	if !decodeBody(w, r, &req) {
		return
	}
	set, ok := m.loadSettings(w)
	if !ok {
		return
	}
	root, err := safeRunDir(set.WebRoot, site.Name, req.Subdir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	site.RootDir = root
	m.applySite(w, r, site, "sites.rundir.update", site.Name+" -> "+root)
}

// findRewriteTemplate 按 id 查内置模板。
func findRewriteTemplate(id string) (RewriteTemplate, bool) {
	for _, t := range rewriteTemplates {
		if t.ID == id {
			return t, true
		}
	}
	return RewriteTemplate{}, false
}
