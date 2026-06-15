// Package dns 实现 DNS 记录管理模块:受管 zone 与记录(A/AAAA/CNAME/MX/TXT/NS/SRV/CAA)的
// 列出/增/改/删。后端二选一:本地 BIND(渲染 zone 文件 + rndc reload)或云 provider(凭证
// AES-GCM 加密落库,接口 + 示例 mock provider)。记录值/类型/域名严格白名单校验挡注入。
// 写操作需 admin,删除需 X-Confirm-Danger,全部审计。
package dns

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
}

// Module 是可开关的 DNS 记录管理模块。
type Module struct {
	st   *dnsStore
	deps Deps
}

// New 建表并返回模块。secret 用于派生 provider 凭证的 AES-GCM 密钥。
// 建表/派生失败直接 panic:模块无法工作。
func New(secret string, st *store.Store, deps Deps) *Module {
	cryp, err := newCryptor(secret)
	if err != nil {
		panic("dns: init cryptor: " + err.Error())
	}
	ds, err := newDNSStore(st, cryp)
	if err != nil {
		panic("dns: init store: " + err.Error())
	}
	return &Module{st: ds, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "dns", Name: "DNS", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "DNS", Icon: "globe", Path: "/dns"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:无外部命令硬依赖(bind 缺失时由 provider.healthy 在 apply 前报错),始终可启用。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // 只读(admin)
	r.Put("/settings", m.handlePutSettings) // 写(admin)

	r.Get("/domains", m.handleListDomains)            // 只读(任意已认证)
	r.Post("/domains", m.handleCreateDomain)          // 写(admin)
	r.Delete("/domains/{id}", m.handleDeleteDomain)   // 危险(admin + 确认)

	r.Get("/domains/{id}/records", m.handleListRecords)              // 只读(任意已认证)
	r.Post("/domains/{id}/records", m.handleCreateRecord)            // 写(admin)
	r.Put("/domains/{id}/records/{rid}", m.handleUpdateRecord)       // 写(admin)
	r.Delete("/domains/{id}/records/{rid}", m.handleDeleteRecord)    // 危险(admin + 确认)
}

// recordInput 是增/改记录的请求体。
type recordInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority"`
}

// validate 校验并规范化记录输入,返回可落库的 Record(不含 ID)。
func (in recordInput) validate() (Record, error) {
	if !validRecordName(in.Name) {
		return Record{}, errBadName
	}
	if !validType(in.Type) {
		return Record{}, errBadType
	}
	if !validValue(in.Type, in.Value) {
		return Record{}, errBadValue
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = 3600
	}
	if !validTTL(ttl) {
		return Record{}, errBadTTL
	}
	if needsPriority(in.Type) && !validPriority(in.Priority) {
		return Record{}, errBadPrio
	}
	prio := in.Priority
	if !needsPriority(in.Type) {
		prio = 0
	}
	return Record{Name: in.Name, Type: in.Type, Value: in.Value, TTL: ttl, Priority: prio}, nil
}

// --- domain handlers ---

func (m *Module) handleListDomains(w http.ResponseWriter, r *http.Request) {
	if !m.authed(w, r) {
		return
	}
	domains, err := m.st.listDomains()
	if err != nil {
		log.Printf("dns: list domains failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": orEmptyDomains(domains)})
}

func (m *Module) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	name := normalizeDomain(in.Name)
	if !validDomain(name) {
		http.Error(w, errBadDomain.Error(), http.StatusBadRequest)
		return
	}
	d, err := m.st.createDomain(name, time.Now().Unix())
	if err != nil {
		log.Printf("dns: create domain failed: %v", err)
		http.Error(w, "create failed (duplicate or db error)", http.StatusBadRequest)
		return
	}
	m.deps.Audit(&uid, "dns.domain.create", "domain="+name, clientIP(r))
	writeJSON(w, http.StatusOK, d)
}

func (m *Module) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	d, err := m.st.getDomain(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}
	if err := m.st.deleteDomain(id); err != nil {
		log.Printf("dns: delete domain failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "dns.domain.delete", "domain="+d.Name, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// --- record handlers ---

func (m *Module) handleListRecords(w http.ResponseWriter, r *http.Request) {
	if !m.authed(w, r) {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if _, err := m.st.getDomain(id); err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}
	recs, err := m.st.listRecords(id)
	if err != nil {
		log.Printf("dns: list records failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": orEmptyRecords(recs)})
}

func (m *Module) handleCreateRecord(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	domain, err := m.st.getDomain(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}
	rec, ok := m.decodeRecord(w, r)
	if !ok {
		return
	}
	saved, err := m.st.createRecord(id, rec)
	if err != nil {
		log.Printf("dns: create record failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	if err := m.applyZone(r.Context(), domain); err != nil {
		// 落地失败:回滚 DB 记录,保持真相源与数据面一致。
		_ = m.st.deleteRecord(id, saved.ID)
		log.Printf("dns: apply zone %q failed: %v", domain.Name, err)
		http.Error(w, "backend apply failed", http.StatusBadGateway)
		return
	}
	m.deps.Audit(&uid, "dns.record.create", recordDetail(domain.Name, saved), clientIP(r))
	writeJSON(w, http.StatusOK, saved)
}

func (m *Module) handleUpdateRecord(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	rid, ok := pathID(w, r, "rid")
	if !ok {
		return
	}
	domain, err := m.st.getDomain(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}
	rec, ok := m.decodeRecord(w, r)
	if !ok {
		return
	}
	if err := m.st.updateRecord(id, rid, rec); err != nil {
		if errors.Is(err, errNotFound) {
			http.Error(w, "record not found", http.StatusNotFound)
			return
		}
		log.Printf("dns: update record failed: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	if err := m.applyZone(r.Context(), domain); err != nil {
		log.Printf("dns: apply zone %q failed: %v", domain.Name, err)
		http.Error(w, "backend apply failed", http.StatusBadGateway)
		return
	}
	rec.ID = rid
	m.deps.Audit(&uid, "dns.record.update", recordDetail(domain.Name, rec), clientIP(r))
	writeJSON(w, http.StatusOK, rec)
}

func (m *Module) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	rid, ok := pathID(w, r, "rid")
	if !ok {
		return
	}
	domain, err := m.st.getDomain(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}
	if err := m.st.deleteRecord(id, rid); err != nil {
		if errors.Is(err, errNotFound) {
			http.Error(w, "record not found", http.StatusNotFound)
			return
		}
		log.Printf("dns: delete record failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	if err := m.applyZone(r.Context(), domain); err != nil {
		log.Printf("dns: apply zone %q failed: %v", domain.Name, err)
		http.Error(w, "backend apply failed", http.StatusBadGateway)
		return
	}
	m.deps.Audit(&uid, "dns.record.delete", "domain="+domain.Name+" rid="+strconv.FormatInt(rid, 10), clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// applyZone 用当前设置构造后端,把该 zone 的全部记录落地。
func (m *Module) applyZone(ctx context.Context, d Domain) error {
	eff, err := m.st.effective()
	if err != nil {
		return err
	}
	be := newBackend(eff)
	if err := be.healthy(); err != nil {
		return err
	}
	recs, err := m.st.listRecords(d.ID)
	if err != nil {
		return err
	}
	return be.apply(ctx, d.Name, recs)
}

// newBackend 按设置选择后端实现。mock 既是测试替身也是云 provider 示例。
func newBackend(s Settings) backend {
	if s.ProviderKind == "mock" {
		return newMockProvider(s.ProviderCreds)
	}
	return newBindBackend(s.BindZoneDir)
}

// --- settings handlers ---

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	eff, credsSet, err := m.st.masked()
	if err != nil {
		log.Printf("dns: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff, "creds_set": credsSet})
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var in Settings
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.ProviderKind != "" && in.ProviderKind != "bind" && in.ProviderKind != "mock" {
		http.Error(w, "provider_kind must be bind or mock", http.StatusBadRequest)
		return
	}
	if err := m.st.saveSettings(in); err != nil {
		log.Printf("dns: settings save failed: %v", err)
		http.Error(w, "settings save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "dns.settings.update", "", clientIP(r))
	eff, credsSet, err := m.st.masked()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": eff, "creds_set": credsSet})
}

// --- helpers ---

func (m *Module) authed(w http.ResponseWriter, r *http.Request) bool {
	if _, role := m.deps.Principal(r); role == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

func (m *Module) decodeRecord(w http.ResponseWriter, r *http.Request) (Record, bool) {
	var in recordInput
	if err := decodeJSON(w, r, &in); err != nil {
		return Record{}, false
	}
	rec, err := in.validate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return Record{}, false
	}
	return rec, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return err
	}
	return nil
}

func pathID(w http.ResponseWriter, r *http.Request, key string) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParamFromCtx(r.Context(), key), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid "+key, http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

// recordDetail 为审计构造非敏感描述。
func recordDetail(zone string, r Record) string {
	return "domain=" + zone + " " + r.Type + " " + r.Name
}

// confirmed 检查危险操作二次确认标记(与其它模块语义一致)。
func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP 从 RemoteAddr 取 IP(与 server 层一致,无代理信任)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// normalizeDomain 规范化域名:去末尾点、转小写。
func normalizeDomain(d string) string {
	out := make([]byte, 0, len(d))
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	s := string(out)
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

func orEmptyDomains(d []Domain) []Domain {
	if d == nil {
		return []Domain{}
	}
	return d
}

func orEmptyRecords(r []Record) []Record {
	if r == nil {
		return []Record{}
	}
	return r
}
