package mail

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockBackend 记录调用,断言口令哈希经后端、不落库,sync 收到全量投影。
type mockBackend struct {
	avail     error
	hashErr   error
	hashedIn  []string      // 传给 hashPassword 的明文(断言口令到了后端)
	syncedMbx []mailboxUser // 最近一次 syncMailboxes 收到的用户
	syncedDom []string
	syncedAls []aliasMeta
	reloads   int
	failSync  bool
}

func newMockBackend() *mockBackend { return &mockBackend{} }

func (b *mockBackend) available() error { return b.avail }

func (b *mockBackend) hashPassword(_ context.Context, pw string) (string, error) {
	if b.hashErr != nil {
		return "", b.hashErr
	}
	b.hashedIn = append(b.hashedIn, pw)
	return "{SHA512-CRYPT}$6$deadbeef$hashed", nil
}

func (b *mockBackend) syncDomains(_ context.Context, _ Settings, domains []string) error {
	if b.failSync {
		return context.DeadlineExceeded
	}
	b.syncedDom = domains
	return nil
}

func (b *mockBackend) syncMailboxes(_ context.Context, _ Settings, boxes []mailboxUser) error {
	if b.failSync {
		return context.DeadlineExceeded
	}
	b.syncedMbx = boxes
	return nil
}

func (b *mockBackend) syncAliases(_ context.Context, _ Settings, aliases []aliasMeta) error {
	if b.failSync {
		return context.DeadlineExceeded
	}
	b.syncedAls = aliases
	return nil
}

func (b *mockBackend) reload(context.Context) error {
	if b.failSync {
		return context.DeadlineExceeded
	}
	b.reloads++
	return nil
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

type auditRec struct {
	count   int
	details []string
}

func newTestModule(t *testing.T, role string, be *mockBackend, ar *auditRec) *Module {
	t.Helper()
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 7, role },
		Audit: func(_ *int64, _, detail, _ string) {
			ar.count++
			ar.details = append(ar.details, detail)
		},
	}
	return New(newTestStore(t), be, deps)
}

func router(m *Module) chi.Router {
	r := chi.NewRouter()
	m.Routes(r)
	return r
}

func do(r chi.Router, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestMetaSwitchable(t *testing.T) {
	m := newTestModule(t, "admin", newMockBackend(), &auditRec{})
	if m.Meta().ID != "mail" || m.Meta().AlwaysOn {
		t.Errorf("mail must be id=mail, not AlwaysOn, got %+v", m.Meta())
	}
	if m.Meta().Category != "网站" {
		t.Errorf("category should be 网站, got %q", m.Meta().Category)
	}
	if nav := m.Nav(); len(nav) != 1 || nav[0].Path != "/mail" || nav[0].Icon != "mail" {
		t.Errorf("nav should be /mail icon mail, got %+v", nav)
	}
}

func TestNonAdminForbidden(t *testing.T) {
	ar := &auditRec{}
	m := newTestModule(t, "operator", newMockBackend(), ar)
	r := router(m)
	cases := []struct{ method, path, body string }{
		{"GET", "/settings", ""},
		{"PUT", "/settings", `{}`},
		{"GET", "/domains", ""},
		{"POST", "/domains", `{"domain":"example.com"}`},
		{"DELETE", "/domains/example.com", ""},
		{"GET", "/mailboxes", ""},
		{"POST", "/mailboxes", `{"address":"bob@example.com","password":"x"}`},
		{"DELETE", "/mailboxes/bob@example.com", ""},
		{"POST", "/mailboxes/bob@example.com/password", `{"password":"x"}`},
		{"GET", "/aliases", ""},
		{"POST", "/aliases", `{"source":"a@example.com","destination":"b@example.com"}`},
		{"DELETE", "/aliases", `{"source":"a@example.com","destination":"b@example.com"}`},
	}
	for _, c := range cases {
		rec := do(r, c.method, c.path, c.body, map[string]string{"X-Confirm-Danger": "1"})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403", c.method, c.path, rec.Code)
		}
	}
	if ar.count != 0 {
		t.Errorf("forbidden requests must not audit, got %d", ar.count)
	}
}

func TestAddDomainAndReject(t *testing.T) {
	be := newMockBackend()
	m := newTestModule(t, "admin", be, &auditRec{})
	r := router(m)
	if rec := do(r, "POST", "/domains", `{"domain":"example.com"}`, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("add domain got %d body=%q", rec.Code, rec.Body.String())
	}
	if len(be.syncedDom) != 1 || be.syncedDom[0] != "example.com" {
		t.Fatalf("backend should receive synced domain, got %v", be.syncedDom)
	}
	if be.reloads == 0 {
		t.Error("add domain should reload backend")
	}
	// 注入域名拒绝。
	for _, bad := range []string{`{"domain":"a;rm -rf.com"}`, `{"domain":"x.com\nevil OK"}`, `{"domain":"notadomain"}`} {
		if rec := do(r, "POST", "/domains", bad, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("inject domain %s should 400, got %d", bad, rec.Code)
		}
	}
}

func TestDeleteDomainRequiresConfirm(t *testing.T) {
	be := newMockBackend()
	ar := &auditRec{}
	m := newTestModule(t, "admin", be, ar)
	r := router(m)
	do(r, "POST", "/domains", `{"domain":"example.com"}`, nil)
	if rec := do(r, "DELETE", "/domains/example.com", "", nil); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	if rec := do(r, "DELETE", "/domains/example.com", "", map[string]string{"X-Confirm-Danger": "1"}); rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed delete got %d", rec.Code)
	}
	doms, _ := m.ds.listDomains()
	if len(doms) != 0 {
		t.Errorf("domain should be deleted, got %v", doms)
	}
}

func TestCreateMailboxPasswordNeverPersisted(t *testing.T) {
	be := newMockBackend()
	ar := &auditRec{}
	m := newTestModule(t, "admin", be, ar)
	r := router(m)
	do(r, "POST", "/domains", `{"domain":"example.com"}`, nil)
	const secret = "SuperSecret123!"
	rec := do(r, "POST", "/mailboxes", `{"address":"bob@example.com","password":"`+secret+`","quota_mb":500}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("create mailbox got %d body=%q", rec.Code, rec.Body.String())
	}
	// 明文口令到了后端哈希。
	if len(be.hashedIn) != 1 || be.hashedIn[0] != secret {
		t.Fatalf("backend should hash plaintext, got %v", be.hashedIn)
	}
	// sync 收到的是哈希,不是明文。
	if len(be.syncedMbx) != 1 || strings.Contains(be.syncedMbx[0].PasswordHash, secret) {
		t.Fatalf("synced hash must not contain plaintext, got %+v", be.syncedMbx)
	}
	if be.syncedMbx[0].PasswordHash == "" {
		t.Fatal("synced mailbox should carry password hash")
	}
	// 扫描整张 mail_mailboxes 不含明文。
	rows, err := m.ds.db.Query(`SELECT address, domain, maildir FROM mail_mailboxes`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a, d, md string
		if err := rows.Scan(&a, &d, &md); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(a+d+md, secret) {
			t.Fatal("password leaked into mail_mailboxes metadata")
		}
	}
	// 审计 detail 不含口令。
	for _, det := range ar.details {
		if strings.Contains(det, secret) {
			t.Fatalf("audit detail leaked password: %q", det)
		}
	}
}

func TestCreateMailboxRejectsBadAddressAndUnknownDomain(t *testing.T) {
	be := newMockBackend()
	m := newTestModule(t, "admin", be, &auditRec{})
	r := router(m)
	do(r, "POST", "/domains", `{"domain":"example.com"}`, nil)
	// 注入地址
	if rec := do(r, "POST", "/mailboxes", `{"address":"a;rm@example.com","password":"pw1234"}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("injection address should 400, got %d", rec.Code)
	}
	// 换行口令
	if rec := do(r, "POST", "/mailboxes", "{\"address\":\"bob@example.com\",\"password\":\"a\\nb\"}", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("newline password should 400, got %d", rec.Code)
	}
	// 域不存在
	if rec := do(r, "POST", "/mailboxes", `{"address":"bob@other.com","password":"pw1234"}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown domain should 400, got %d", rec.Code)
	}
	// 负配额
	if rec := do(r, "POST", "/mailboxes", `{"address":"bob@example.com","password":"pw1234","quota_mb":-1}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("negative quota should 400, got %d", rec.Code)
	}
	if len(be.hashedIn) != 0 {
		t.Errorf("no password should be hashed on validation failure, got %v", be.hashedIn)
	}
}

func TestMailboxPasswordChangeNotInAudit(t *testing.T) {
	be := newMockBackend()
	ar := &auditRec{}
	m := newTestModule(t, "admin", be, ar)
	r := router(m)
	do(r, "POST", "/domains", `{"domain":"example.com"}`, nil)
	do(r, "POST", "/mailboxes", `{"address":"alice@example.com","password":"OldPass1"}`, nil)
	const secret = "N3wPass!"
	rec := do(r, "POST", "/mailboxes/alice@example.com/password", `{"password":"`+secret+`"}`, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("password change got %d", rec.Code)
	}
	if be.hashedIn[len(be.hashedIn)-1] != secret {
		t.Fatal("backend should receive new plaintext to hash")
	}
	for _, d := range ar.details {
		if strings.Contains(d, secret) {
			t.Fatalf("audit detail leaked password: %q", d)
		}
	}
}

func TestDeleteMailboxRequiresConfirmAndAudits(t *testing.T) {
	be := newMockBackend()
	ar := &auditRec{}
	m := newTestModule(t, "admin", be, ar)
	r := router(m)
	do(r, "POST", "/domains", `{"domain":"example.com"}`, nil)
	do(r, "POST", "/mailboxes", `{"address":"bob@example.com","password":"pw1234"}`, nil)
	before := ar.count
	if rec := do(r, "DELETE", "/mailboxes/bob@example.com", "", nil); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	if ar.count != before {
		t.Fatal("unconfirmed delete must not audit")
	}
	if rec := do(r, "DELETE", "/mailboxes/bob@example.com", "", map[string]string{"X-Confirm-Danger": "1"}); rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed delete got %d", rec.Code)
	}
	boxes, _ := m.ds.listMailboxes()
	if len(boxes) != 0 {
		t.Errorf("mailbox should be deleted, got %v", boxes)
	}
}

func TestAliasAddDeleteAndReject(t *testing.T) {
	be := newMockBackend()
	m := newTestModule(t, "admin", be, &auditRec{})
	r := router(m)
	if rec := do(r, "POST", "/aliases", `{"source":"info@example.com","destination":"bob@example.com"}`, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("add alias got %d body=%q", rec.Code, rec.Body.String())
	}
	if len(be.syncedAls) != 1 {
		t.Fatalf("backend should receive alias, got %v", be.syncedAls)
	}
	// 注入目标拒绝。
	if rec := do(r, "POST", "/aliases", `{"source":"info@example.com","destination":"evil@x.com\nrm"}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("injection dest should 400, got %d", rec.Code)
	}
	// 删除需确认。
	if rec := do(r, "DELETE", "/aliases", `{"source":"info@example.com","destination":"bob@example.com"}`, nil); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete alias without confirm should 428, got %d", rec.Code)
	}
	if rec := do(r, "DELETE", "/aliases", `{"source":"info@example.com","destination":"bob@example.com"}`, map[string]string{"X-Confirm-Danger": "1"}); rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed delete alias got %d", rec.Code)
	}
	aliases, _ := m.ds.listAliases()
	if len(aliases) != 0 {
		t.Errorf("alias should be deleted, got %v", aliases)
	}
}

func TestSettingsRoundTripAndDefaults(t *testing.T) {
	m := newTestModule(t, "admin", newMockBackend(), &auditRec{})
	r := router(m)
	rec := do(r, "GET", "/settings", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/var/vmail") {
		t.Fatalf("default mail_store_dir missing: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(r, "PUT", "/settings", `{"mail_store_dir":"/srv/vmail","postfix_config_dir":"/opt/postfix"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put settings got %d", rec.Code)
	}
	eff, err := m.ds.effective()
	if err != nil || eff.MailStoreDir != "/srv/vmail" || eff.PostfixConfigDir != "/opt/postfix" {
		t.Fatalf("settings not persisted: %+v %v", eff, err)
	}
	// 相对路径拒绝。
	if rec := do(r, "PUT", "/settings", `{"mail_store_dir":"relative/path"}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("relative path should 400, got %d", rec.Code)
	}
}

func TestHealthCheckReflectsBackend(t *testing.T) {
	be := newMockBackend()
	m := newTestModule(t, "admin", be, &auditRec{})
	if err := m.HealthCheck(); err != nil {
		t.Errorf("available backend should pass health, got %v", err)
	}
	be.avail = context.Canceled
	if m.HealthCheck() == nil {
		t.Error("unavailable backend should fail health")
	}
}

func TestCreateMailboxBackendFailureStillAudits(t *testing.T) {
	be := newMockBackend()
	be.hashErr = context.DeadlineExceeded
	ar := &auditRec{}
	m := newTestModule(t, "admin", be, ar)
	r := router(m)
	do(r, "POST", "/domains", `{"domain":"example.com"}`, nil)
	before := ar.count
	rec := do(r, "POST", "/mailboxes", `{"address":"dave@example.com","password":"pw1234"}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("hash failure should 502, got %d", rec.Code)
	}
	if ar.count != before+1 {
		t.Fatalf("failed create should audit once, got %d", ar.count-before)
	}
	// 哈希失败时不应落邮箱元数据。
	boxes, _ := m.ds.listMailboxes()
	if len(boxes) != 0 {
		t.Fatalf("failed create must not persist meta, got %d", len(boxes))
	}
}
