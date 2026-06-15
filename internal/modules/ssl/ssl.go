// Package ssl 实现 SSL 证书模块:基于 ACME CLI(acme.sh / certbot)签发/续期/管理
// Let's Encrypt 证书,支持自定义证书上传、到期监控与自动续期。
//
// 证书元数据(域名/颁发者/到期/路径/自动续期)存自建表;私钥内容绝不入库、
// 不经接口返回、不进日志,仅以 0600 文件落盘。可配置路径(证书目录/ACME 账户目录/
// webroot)持久化在自建设置表,admin 可改。
package ssl

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string)
	Audit     func(userID *int64, action, detail, ip string)
}

// 设置键与默认值。证书/账户目录与 aaPanel 习惯对齐。
const (
	keyCertDir = "cert_dir"
	keyAcmeDir = "acme_dir"
	keyWebroot = "webroot"

	defaultCertDir = "/www/server/panel/vhost/cert"
	defaultAcmeDir = "/www/server/panel/vhost/acme"
	defaultWebroot = "/www/wwwroot"
)

// renewWindow:证书在距到期此秒数内即视为需续期(30 天)。
const renewWindow int64 = 30 * 24 * 3600

// Module 是可开关的 SSL 证书模块。
type Module struct {
	ss   *sslStore
	acme ACME
	deps Deps
}

// New 建表并返回模块。acme 为 nil 时按 DetectACME 探测(CLI 不在则 HealthCheck 拒绝启用)。
// 建表失败直接 panic:模块无法工作。
func New(st *store.Store, acme ACME, deps Deps) *Module {
	ss, err := newSSLStore(st)
	if err != nil {
		panic("ssl: init store: " + err.Error())
	}
	if acme == nil {
		// 探测失败不致命:HealthCheck 会拦住启用;此处留 nil 由 HealthCheck 报错。
		acme, _ = DetectACME()
	}
	return &Module{ss: ss, acme: acme, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "ssl", Name: "SSL证书", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "SSL证书", Icon: "shield-check", Path: "/ssl"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:ACME CLI 不在 PATH 则不允许启用。
func (m *Module) HealthCheck() error {
	if m.acme == nil {
		_, err := DetectACME()
		return err
	}
	return m.acme.Available()
}

func (m *Module) Routes(r module.Router) {
	r.Get("/certs", m.handleList)                  // 只读
	r.Post("/certs", m.handleIssue)                // 写:签发
	r.Post("/certs/upload", m.handleUpload)        // 写:上传自定义证书
	r.Post("/certs/{id}/renew", m.handleRenew)     // 写:手动续期
	r.Post("/certs/{id}/auto/{verb:on|off}", m.handleAutoRenew) // 写:开关自动续期
	r.Delete("/certs/{id}", m.handleDelete)        // 删除:admin
	r.Post("/renew-due", m.handleRenewDue)         // 写:批量续期到期证书
	r.Get("/settings", m.handleGetSettings)        // 读:admin
	r.Put("/settings", m.handlePutSettings)        // 写:admin
}

// ---- handlers ----

type issueRequest struct {
	Domains   []string `json:"domains"`
	Challenge string   `json:"challenge"`
	Webroot   string   `json:"webroot"`    // 可选,覆盖默认 webroot
	DNSPlugin string   `json:"dns_plugin"` // dns 挑战的 provider,空=手动
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	certs, err := m.ss.list()
	if err != nil {
		log.Printf("ssl: list failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if certs == nil {
		certs = []Cert{}
	}
	writeJSON(w, http.StatusOK, certs)
}

func (m *Module) handleIssue(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req issueRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !ValidDomains(req.Domains) {
		http.Error(w, "invalid domain", http.StatusBadRequest)
		return
	}
	ch := ChallengeType(req.Challenge)
	if !validChallenge(ch) {
		http.Error(w, "invalid challenge", http.StatusBadRequest)
		return
	}
	webroot, err := m.resolveWebroot(req.Webroot)
	if err != nil {
		http.Error(w, "invalid webroot", http.StatusBadRequest)
		return
	}
	if req.DNSPlugin != "" && !validDNSPlugin(req.DNSPlugin) {
		http.Error(w, "invalid dns plugin", http.StatusBadRequest)
		return
	}

	primary := req.Domains[0]
	certPath, keyPath, err := m.certPaths(primary)
	if err != nil {
		http.Error(w, "invalid cert path", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		log.Printf("ssl: mkdir cert dir failed: %v", err)
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}

	issueErr := m.acme.Issue(IssueRequest{
		Domains: req.Domains, Challenge: ch, Webroot: webroot,
		DNSPlugin: req.DNSPlugin, KeyPath: keyPath, CertPath: certPath,
	})
	outcome := "ok"
	if issueErr != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "ssl.issue", primary+" "+string(ch)+" "+outcome, clientIP(r))
	if issueErr != nil {
		log.Printf("ssl: issue %s failed: %v", primary, issueErr)
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	if err := secureKeyFile(keyPath); err != nil {
		log.Printf("ssl: chmod key failed: %v", err)
	}

	id, err := m.ss.create(Cert{
		Domains: strings.Join(req.Domains, ","), Issuer: "letsencrypt",
		Challenge: string(ch), CertPath: certPath, KeyPath: keyPath,
		NotAfter: readExpiry(certPath), AutoRenew: true, CreatedBy: &uid,
	})
	if err != nil {
		log.Printf("ssl: record create failed: %v", err)
		http.Error(w, "issue recorded failed", http.StatusInternalServerError)
		return
	}
	c, _ := m.ss.get(id)
	writeJSON(w, http.StatusCreated, c)
}

type uploadRequest struct {
	Domains []string `json:"domains"`
	Cert    string   `json:"cert"` // 全链 PEM
	Key     string   `json:"key"`  // 私钥 PEM
}

func (m *Module) handleUpload(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req uploadRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !ValidDomains(req.Domains) {
		http.Error(w, "invalid domain", http.StatusBadRequest)
		return
	}
	notAfter, err := parseCertExpiry([]byte(req.Cert))
	if err != nil {
		http.Error(w, "invalid certificate PEM", http.StatusBadRequest)
		return
	}
	if !validPrivateKeyPEM([]byte(req.Key)) {
		http.Error(w, "invalid private key PEM", http.StatusBadRequest)
		return
	}
	primary := req.Domains[0]
	certPath, keyPath, err := m.certPaths(primary)
	if err != nil {
		http.Error(w, "invalid cert path", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		log.Printf("ssl: mkdir cert dir failed: %v", err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(certPath, []byte(req.Cert), 0o644); err != nil {
		log.Printf("ssl: write cert failed: %v", err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(keyPath, []byte(req.Key), 0o600); err != nil {
		log.Printf("ssl: write key failed: %v", err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	id, err := m.ss.create(Cert{
		Domains: strings.Join(req.Domains, ","), Issuer: "uploaded",
		Challenge: "upload", CertPath: certPath, KeyPath: keyPath,
		NotAfter: notAfter, AutoRenew: false, CreatedBy: &uid,
	})
	if err != nil {
		log.Printf("ssl: upload record failed: %v", err)
		http.Error(w, "upload recorded failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "ssl.upload", primary, clientIP(r))
	c, _ := m.ss.get(id)
	writeJSON(w, http.StatusCreated, c)
}

func (m *Module) handleRenew(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "cert not found", http.StatusNotFound)
		return
	}
	domains := domainList(c.Domains)
	if len(domains) == 0 || !ValidDomain(domains[0]) {
		http.Error(w, "cert has invalid domain", http.StatusBadRequest)
		return
	}
	renewErr := m.acme.Renew(domains[0], c.KeyPath, c.CertPath)
	outcome := "ok"
	if renewErr != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "ssl.renew", domains[0]+" "+outcome, clientIP(r))
	if renewErr != nil {
		log.Printf("ssl: renew %s failed: %v", domains[0], renewErr)
		http.Error(w, "renew failed", http.StatusInternalServerError)
		return
	}
	_ = secureKeyFile(c.KeyPath)
	_ = m.ss.markRenewed(id, readExpiry(c.CertPath))
	updated, _ := m.ss.get(id)
	writeJSON(w, http.StatusOK, updated)
}

func (m *Module) handleAutoRenew(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := m.ss.get(id); err != nil {
		http.Error(w, "cert not found", http.StatusNotFound)
		return
	}
	on := chi.URLParamFromCtx(r.Context(), "verb") == "on"
	if err := m.ss.setAutoRenew(id, on); err != nil {
		log.Printf("ssl: set auto-renew failed: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "ssl.auto", strconv.FormatInt(id, 10)+" "+chi.URLParamFromCtx(r.Context(), "verb"), clientIP(r))
	c, _ := m.ss.get(id)
	writeJSON(w, http.StatusOK, c)
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "cert not found", http.StatusNotFound)
		return
	}
	if err := m.ss.delete(id); err != nil {
		log.Printf("ssl: delete failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	// 删除落盘文件(best-effort);失败仅记日志,记录已删。
	_ = os.Remove(c.CertPath)
	_ = os.Remove(c.KeyPath)
	m.deps.Audit(&uid, "ssl.delete", strconv.FormatInt(id, 10), clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// handleRenewDue 批量续期距到期 renewWindow 内、开启自动续期的证书。
func (m *Module) handleRenewDue(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	due, err := m.ss.autoRenewable(nowUnix() + renewWindow)
	if err != nil {
		log.Printf("ssl: list due failed: %v", err)
		http.Error(w, "renew-due failed", http.StatusInternalServerError)
		return
	}
	var renewed, failed int
	for _, c := range due {
		domains := domainList(c.Domains)
		if len(domains) == 0 || !ValidDomain(domains[0]) {
			failed++
			continue
		}
		if err := m.acme.Renew(domains[0], c.KeyPath, c.CertPath); err != nil {
			log.Printf("ssl: auto-renew %s failed: %v", domains[0], err)
			failed++
			continue
		}
		_ = secureKeyFile(c.KeyPath)
		_ = m.ss.markRenewed(c.ID, readExpiry(c.CertPath))
		renewed++
	}
	m.deps.Audit(&uid, "ssl.renew-due", strconv.Itoa(renewed)+" ok "+strconv.Itoa(failed)+" failed", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]int{"renewed": renewed, "failed": failed})
}

type settingsResponse struct {
	CertDir string `json:"cert_dir"`
	AcmeDir string `json:"acme_dir"`
	Webroot string `json:"webroot"`
	Backend string `json:"backend"`
}

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	s := m.settings()
	backend := ""
	if m.acme != nil {
		backend = m.acme.Name()
	}
	writeJSON(w, http.StatusOK, settingsResponse{
		CertDir: s.certDir, AcmeDir: s.acmeDir, Webroot: s.webroot, Backend: backend,
	})
}

type settingsRequest struct {
	CertDir string `json:"cert_dir"`
	AcmeDir string `json:"acme_dir"`
	Webroot string `json:"webroot"`
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var req settingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	for _, p := range []string{req.CertDir, req.AcmeDir, req.Webroot} {
		if p != "" && !validAbsDir(p) {
			http.Error(w, "paths must be absolute, no traversal", http.StatusBadRequest)
			return
		}
	}
	set := func(key, v string) error {
		if v == "" {
			return nil
		}
		return m.ss.setSetting(key, v)
	}
	if err := set(keyCertDir, req.CertDir); err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	if err := set(keyAcmeDir, req.AcmeDir); err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	if err := set(keyWebroot, req.Webroot); err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "ssl.settings", "updated", clientIP(r))
	m.handleGetSettings(w, r)
}

// ---- helpers ----

type resolvedSettings struct {
	certDir, acmeDir, webroot string
}

func (m *Module) settings() resolvedSettings {
	cd, _ := m.ss.getSetting(keyCertDir, defaultCertDir)
	ad, _ := m.ss.getSetting(keyAcmeDir, defaultAcmeDir)
	wr, _ := m.ss.getSetting(keyWebroot, defaultWebroot)
	return resolvedSettings{certDir: cd, acmeDir: ad, webroot: wr}
}

// certPaths 在配置的证书目录下,按主域名构造 fullchain/key 落盘路径。域名已校验,无注入。
func (m *Module) certPaths(primary string) (certPath, keyPath string, err error) {
	if !ValidDomain(primary) {
		return "", "", errNoCert
	}
	dir := filepath.Join(m.settings().certDir, sanitizeDomainDir(primary))
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"), nil
}

// resolveWebroot 取请求 webroot,空则用设置默认;非空必须是合法绝对目录。
func (m *Module) resolveWebroot(reqWebroot string) (string, error) {
	if reqWebroot == "" {
		return m.settings().webroot, nil
	}
	if !validAbsDir(reqWebroot) {
		return "", errNoCert
	}
	return reqWebroot, nil
}

func (m *Module) requireWriter(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// sanitizeDomainDir 把主域名转成安全目录名:通配 "*." 前缀替为 "wildcard."。
// 域名已通过 ValidDomain,无路径分隔符。
func sanitizeDomainDir(d string) string {
	return strings.ReplaceAll(d, "*.", "wildcard.")
}

// validAbsDir 校验路径为绝对路径、Clean 后不含 ".." 逃逸。
func validAbsDir(p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	if strings.ContainsAny(p, ";|&$`<>\n\r\t\x00") {
		return false
	}
	clean := filepath.Clean(p)
	return !strings.Contains(clean, "..")
}

// validDNSPlugin 限制 DNS 插件名为安全标识符(acme.sh dns_xxx / certbot 插件名)。
var dnsPluginRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func validDNSPlugin(s string) bool { return dnsPluginRe.MatchString(s) }

// secureKeyFile 把私钥文件权限收紧到 0600。
func secureKeyFile(path string) error { return os.Chmod(path, 0o600) }

// readExpiry 读取证书文件并解析到期时间;失败返回 0(未知)。
func readExpiry(certPath string) int64 {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return 0
	}
	exp, err := parseCertExpiry(b)
	if err != nil {
		return 0
	}
	return exp
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := chi.URLParamFromCtx(r.Context(), "id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// timeNow 间接化 time.Now,便于测试覆盖到期窗口逻辑。
var timeNow = time.Now

func nowUnix() int64 { return timeNow().Unix() }
