// Package mail 实现邮局/邮件服务器管理模块(对标 aaPanel 邮局):邮件域、邮箱(地址+
// 口令+配额)、别名/转发的增删改。XPanel 的库是权威数据源,每次变更后把全量数据投影成
// postfix 虚拟域/邮箱/别名 map(postmap)与 dovecot 用户库,再 reload 两个服务。
// 口令绝不明文落 XPanel 的库 —— 经 doveadm pw 哈希后写入 dovecot 用户库;域名/邮箱地址
// 严格白名单挡注入;删除等危险操作需 X-Confirm-Danger;所有变更审计。
package mail

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的邮局管理模块。
type Module struct {
	ds   *dataStore
	be   mailBackend
	deps Deps
}

// New 建表并返回模块。建表失败直接 panic:模块无法工作。
// be 为 nil 时用默认 postfix/dovecot 后端。
func New(st *store.Store, be mailBackend, deps Deps) *Module {
	ds, err := newDataStore(st)
	if err != nil {
		panic("mail: init store: " + err.Error())
	}
	if be == nil {
		be = newPostfixDovecot()
	}
	return &Module{ds: ds, be: be, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "mail", Name: "邮局", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "邮局", Icon: "mail", Path: "/mail"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:postfix 不在 PATH 则不允许启用。
func (m *Module) HealthCheck() error { return m.be.available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // 只读(admin)
	r.Put("/settings", m.handlePutSettings) // 写(admin)

	r.Get("/domains", m.handleListDomains)              // 列出(admin)
	r.Post("/domains", m.handleAddDomain)               // 添加(admin)
	r.Delete("/domains/{domain}", m.handleDeleteDomain) // 删除(admin + 危险确认)

	r.Get("/mailboxes", m.handleListMailboxes)                       // 列出(admin)
	r.Post("/mailboxes", m.handleCreateMailbox)                      // 创建(admin)
	r.Delete("/mailboxes/{address}", m.handleDeleteMailbox)          // 删除(admin + 危险确认)
	r.Post("/mailboxes/{address}/password", m.handleMailboxPassword) // 改密(admin)

	r.Get("/aliases", m.handleListAliases)    // 列出(admin)
	r.Post("/aliases", m.handleAddAlias)      // 添加(admin)
	r.Delete("/aliases", m.handleDeleteAlias) // 删除(admin + 危险确认)
}

// --- 邮件域 ---

type domainRequest struct {
	Domain string `json:"domain"`
}

func (m *Module) handleListDomains(w http.ResponseWriter, r *http.Request) {
	if !m.requireAdmin(w, r) {
		return
	}
	doms, err := m.ds.listDomains()
	if err != nil {
		log.Printf("mail: list domains failed: %v", err)
		http.Error(w, "domains unavailable", http.StatusInternalServerError)
		return
	}
	if doms == nil {
		doms = []domainMeta{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": doms})
}

func (m *Module) handleAddDomain(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdminUID(w, r)
	if !ok {
		return
	}
	var req domainRequest
	if err := decodeBody(w, r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validDomain(req.Domain) {
		http.Error(w, errInvalidDomain.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ds.addDomain(req.Domain); err != nil {
		log.Printf("mail: add domain failed: %v", err)
		http.Error(w, "domain add failed", http.StatusInternalServerError)
		return
	}
	serr := m.syncDomains(r.Context())
	m.auditOutcome(uid, "mail.domain.add", "domain="+req.Domain, serr, r)
	if serr != nil {
		http.Error(w, "mail backend sync failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdminUID(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	domain := chi.URLParamFromCtx(r.Context(), "domain")
	if !validDomain(domain) {
		http.Error(w, errInvalidDomain.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ds.deleteDomain(domain); err != nil {
		log.Printf("mail: delete domain failed: %v", err)
		http.Error(w, "domain delete failed", http.StatusInternalServerError)
		return
	}
	serr := m.syncDomains(r.Context())
	m.auditOutcome(uid, "mail.domain.delete", "domain="+domain, serr, r)
	if serr != nil {
		http.Error(w, "mail backend sync failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- 邮箱 ---

type mailboxRequest struct {
	Address  string `json:"address"`
	Password string `json:"password"`
	QuotaMB  int64  `json:"quota_mb"`
}

func (m *Module) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	if !m.requireAdmin(w, r) {
		return
	}
	boxes, err := m.ds.listMailboxes()
	if err != nil {
		log.Printf("mail: list mailboxes failed: %v", err)
		http.Error(w, "mailboxes unavailable", http.StatusInternalServerError)
		return
	}
	if boxes == nil {
		boxes = []mailboxMeta{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mailboxes": boxes})
}

func (m *Module) handleCreateMailbox(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdminUID(w, r)
	if !ok {
		return
	}
	var req mailboxRequest
	if err := decodeBody(w, r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validEmail(req.Address) {
		http.Error(w, errInvalidEmail.Error(), http.StatusBadRequest)
		return
	}
	if !validPassword(req.Password) {
		http.Error(w, errInvalidPassword.Error(), http.StatusBadRequest)
		return
	}
	if req.QuotaMB < 0 {
		http.Error(w, errInvalidQuota.Error(), http.StatusBadRequest)
		return
	}
	_, domain, _ := splitEmail(req.Address)
	has, err := m.ds.hasDomain(domain)
	if err != nil {
		http.Error(w, "domain lookup failed", http.StatusInternalServerError)
		return
	}
	if !has {
		http.Error(w, "mailbox domain must be an existing mail domain", http.StatusBadRequest)
		return
	}

	hash, err := m.be.hashPassword(r.Context(), req.Password)
	if err != nil {
		// 后端失败:不落库、不审计成功。仅记一次失败审计。
		m.deps.Audit(&uid, "mail.mailbox.create", "address="+req.Address+" failed", m.clientIP(r))
		log.Printf("mail: hash password failed: %v", err)
		http.Error(w, "mail backend password hashing failed", http.StatusBadGateway)
		return
	}
	// maildir 相对 virtual_mailbox_base;domain/local 均已过白名单(无 ..、无 /),
	// 用 SafeJoin 在 store 根下构造再转回相对形式,拒绝任何越界。
	maildir, err := safeMaildir(domain, localOf(req.Address))
	if err != nil {
		http.Error(w, "invalid mailbox path", http.StatusBadRequest)
		return
	}
	if err := m.ds.upsertMailbox(mailboxMeta{Address: req.Address, Domain: domain, Maildir: maildir, QuotaMB: req.QuotaMB}); err != nil {
		log.Printf("mail: persist mailbox failed: %v", err)
		http.Error(w, "mailbox persist failed", http.StatusInternalServerError)
		return
	}
	serr := m.syncMailboxes(r.Context(), req.Address, hash)
	// 审计 detail 绝不含口令。
	m.auditOutcome(uid, "mail.mailbox.create", "address="+req.Address, serr, r)
	if serr != nil {
		http.Error(w, "mail backend sync failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdminUID(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	address := chi.URLParamFromCtx(r.Context(), "address")
	if !validEmail(address) {
		http.Error(w, errInvalidEmail.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ds.deleteMailbox(address); err != nil {
		log.Printf("mail: delete mailbox failed: %v", err)
		http.Error(w, "mailbox delete failed", http.StatusInternalServerError)
		return
	}
	serr := m.syncMailboxes(r.Context(), "", "")
	m.auditOutcome(uid, "mail.mailbox.delete", "address="+address, serr, r)
	if serr != nil {
		http.Error(w, "mail backend sync failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleMailboxPassword(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdminUID(w, r)
	if !ok {
		return
	}
	address := chi.URLParamFromCtx(r.Context(), "address")
	if !validEmail(address) {
		http.Error(w, errInvalidEmail.Error(), http.StatusBadRequest)
		return
	}
	var req mailboxRequest
	if err := decodeBody(w, r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validPassword(req.Password) {
		http.Error(w, errInvalidPassword.Error(), http.StatusBadRequest)
		return
	}
	hash, err := m.be.hashPassword(r.Context(), req.Password)
	if err != nil {
		m.deps.Audit(&uid, "mail.mailbox.password", "address="+address+" failed", m.clientIP(r))
		log.Printf("mail: hash password failed: %v", err)
		http.Error(w, "mail backend password hashing failed", http.StatusBadGateway)
		return
	}
	serr := m.syncMailboxes(r.Context(), address, hash)
	// detail 绝不含口令。
	m.auditOutcome(uid, "mail.mailbox.password", "address="+address, serr, r)
	if serr != nil {
		http.Error(w, "mail backend sync failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- 别名/转发 ---

type aliasRequest struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

func (m *Module) handleListAliases(w http.ResponseWriter, r *http.Request) {
	if !m.requireAdmin(w, r) {
		return
	}
	aliases, err := m.ds.listAliases()
	if err != nil {
		log.Printf("mail: list aliases failed: %v", err)
		http.Error(w, "aliases unavailable", http.StatusInternalServerError)
		return
	}
	if aliases == nil {
		aliases = []aliasMeta{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"aliases": aliases})
}

func (m *Module) handleAddAlias(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdminUID(w, r)
	if !ok {
		return
	}
	var req aliasRequest
	if err := decodeBody(w, r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// source 必须是本域邮箱地址;destination 是任意合法邮箱(可外部转发)。
	if !validEmail(req.Source) || !validEmail(req.Destination) {
		http.Error(w, errInvalidEmail.Error(), http.StatusBadRequest)
		return
	}
	_, srcDomain, _ := splitEmail(req.Source)
	has, err := m.ds.hasDomain(srcDomain)
	if err != nil {
		http.Error(w, "domain lookup failed", http.StatusInternalServerError)
		return
	}
	if !has {
		http.Error(w, "alias source must be an existing mail domain", http.StatusBadRequest)
		return
	}
	if err := m.ds.addAlias(req.Source, req.Destination); err != nil {
		log.Printf("mail: add alias failed: %v", err)
		http.Error(w, "alias add failed", http.StatusInternalServerError)
		return
	}
	serr := m.syncAliases(r.Context())
	m.auditOutcome(uid, "mail.alias.add", "source="+req.Source+" dest="+req.Destination, serr, r)
	if serr != nil {
		http.Error(w, "mail backend sync failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdminUID(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	var req aliasRequest
	if err := decodeBody(w, r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validEmail(req.Source) || !validEmail(req.Destination) {
		http.Error(w, errInvalidEmail.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ds.deleteAlias(req.Source, req.Destination); err != nil {
		log.Printf("mail: delete alias failed: %v", err)
		http.Error(w, "alias delete failed", http.StatusInternalServerError)
		return
	}
	serr := m.syncAliases(r.Context())
	m.auditOutcome(uid, "mail.alias.delete", "source="+req.Source+" dest="+req.Destination, serr, r)
	if serr != nil {
		http.Error(w, "mail backend sync failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Settings handlers ---

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if !m.requireAdmin(w, r) {
		return
	}
	eff, err := m.ds.effective()
	if err != nil {
		log.Printf("mail: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff})
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdminUID(w, r)
	if !ok {
		return
	}
	var in Settings
	if err := decodeBody(w, r, &in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// 路径设置非空则必须绝对、cleaned、无 ..、无控制字符与元字符(挡越界覆写/注入,
	// 空值由默认兜底)。模块随后会往这些路径写内容并 postmap,未约束等于任意主机写。
	for _, p := range []string{in.PostfixConfigDir, in.DovecotConfigDir, in.MailStoreDir,
		in.VirtualMailboxFile, in.VirtualDomainFile, in.VirtualAliasFile} {
		if p == "" {
			continue
		}
		if err := validAbsPath(p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := m.ds.save(in); err != nil {
		log.Printf("mail: settings save failed: %v", err)
		http.Error(w, "settings save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "mail.settings.update", "", m.clientIP(r))
	eff, err := m.ds.effective()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff})
}

// --- sync 投影:把 XPanel 的库全量重写到 postfix/dovecot ---

// syncDomains 用最新全量域列表重写虚拟域 map 并 reload。
func (m *Module) syncDomains(ctx context.Context) error {
	eff, err := m.ds.effective()
	if err != nil {
		return err
	}
	doms, err := m.ds.listDomains()
	if err != nil {
		return err
	}
	var names []string
	for _, d := range doms {
		if d.Enabled {
			names = append(names, d.Domain)
		}
	}
	if err := m.be.syncDomains(ctx, eff, names); err != nil {
		return err
	}
	return m.be.reload(ctx)
}

// syncMailboxes 用最新全量邮箱重写虚拟邮箱 map 与 dovecot 用户库并 reload。
// newAddr/newHash 非空时,把该地址的口令哈希并入(改密/创建);其余邮箱保留既有哈希。
// 注:既有哈希不落 XPanel 库,故重建用户库时其它邮箱沿用 dovecot 现有 users 文件中的行 ——
// 这里只能重写被本次操作触及的地址;为保持 users 文件全量一致,改密以单地址增量交给后端。
func (m *Module) syncMailboxes(ctx context.Context, changedAddr, changedHash string) error {
	eff, err := m.ds.effective()
	if err != nil {
		return err
	}
	boxes, err := m.ds.listMailboxes()
	if err != nil {
		return err
	}
	users := make([]mailboxUser, 0, len(boxes))
	for _, b := range boxes {
		u := mailboxUser{Address: b.Address, Maildir: b.Maildir, QuotaMB: b.QuotaMB}
		if b.Address == changedAddr {
			u.PasswordHash = changedHash
		}
		users = append(users, u)
	}
	if err := m.be.syncMailboxes(ctx, eff, users); err != nil {
		return err
	}
	return m.be.reload(ctx)
}

// syncAliases 用最新全量别名重写虚拟别名 map 并 reload。
func (m *Module) syncAliases(ctx context.Context) error {
	eff, err := m.ds.effective()
	if err != nil {
		return err
	}
	aliases, err := m.ds.listAliases()
	if err != nil {
		return err
	}
	if err := m.be.syncAliases(ctx, eff, aliases); err != nil {
		return err
	}
	return m.be.reload(ctx)
}

// --- 辅助 ---

func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return false
	}
	return true
}

// requireAdminUID 同 requireAdmin,但返回 userID 供审计。
func (m *Module) requireAdminUID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// auditOutcome 写一条带 ok/failed 后缀的审计,detail 由调用方保证不含口令。
func (m *Module) auditOutcome(uid int64, action, detail string, err error, r *http.Request) {
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, action, detail+" "+outcome, m.clientIP(r))
}

// confirmed 检查危险操作的二次确认标记(与其它模块语义一致)。
func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
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

// safeMaildir 构造相对 virtual_mailbox_base 的 maildir("<domain>/<local>/")。
// domain/local 已过白名单;这里用 filepath.Join 在固定根下规整后断言仍在根内且无 ..,
// 作纵深防御挡任何越界写入。
func safeMaildir(domain, local string) (string, error) {
	const root = "/"
	joined := filepath.Join(root, domain, local)
	rel := strings.TrimPrefix(joined, root)
	if rel == joined || rel == "" || strings.Contains(rel, "..") {
		return "", errMaildirEscape
	}
	return rel + "/", nil
}

var errMaildirEscape = errors.New("maildir escapes mail store root")

// localOf 返回邮箱地址 @ 前的 local-part(调用方已确保 addr 合法)。
func localOf(addr string) string {
	if i := strings.IndexByte(addr, '@'); i > 0 {
		return addr[:i]
	}
	return addr
}
