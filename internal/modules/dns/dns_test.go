package dns

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestModule(t *testing.T, role string, audited *int) (*Module, chi.Router) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	m := New("test-secret", st, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(_ *int64, _, _, _ string) { *audited++ },
	})
	r := chi.NewRouter()
	m.Routes(r)
	return m, r
}

func do(r chi.Router, method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestMetaSwitchable(t *testing.T) {
	m, _ := newTestModule(t, "admin", new(int))
	meta := m.Meta()
	if meta.ID != "dns" || meta.Name != "DNS" || meta.Category != "网站" || meta.AlwaysOn {
		t.Errorf("unexpected meta: %+v", meta)
	}
}

func TestNav(t *testing.T) {
	m, _ := newTestModule(t, "admin", new(int))
	nav := m.Nav()
	if len(nav) != 1 || nav[0].Path != "/dns" {
		t.Errorf("unexpected nav: %+v", nav)
	}
}

func TestCreateDomainRequiresAdmin(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "readonly", &audited)
	rec := do(r, "POST", "/domains", map[string]string{"name": "example.com"}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create domain should be 403, got %d", rec.Code)
	}
	if audited != 0 {
		t.Fatalf("forbidden must not audit, got %d", audited)
	}
}

func TestCreateDomainRejectsBadName(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "POST", "/domains", map[string]string{"name": "evil.com;rndc reload"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad domain should 400, got %d", rec.Code)
	}
}

func TestListDomainsAllowsReadonly(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "readonly", &audited)
	rec := do(r, "GET", "/domains", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("readonly list should be 200, got %d", rec.Code)
	}
}

func TestDeleteDomainNeedsConfirm(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)
	d, _ := m.st.createDomain("example.com", 1)
	id := jstr(d.ID)
	// 无确认头 → 428
	rec := do(r, "DELETE", "/domains/"+id, nil, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	// 带确认头 → 204
	rec = do(r, "DELETE", "/domains/"+id, nil, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete with confirm should 204, got %d", rec.Code)
	}
	if audited == 0 {
		t.Fatal("delete must audit")
	}
}

func TestCreateRecordValidationAndApply(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)
	// 用 mock provider 后端,配置凭证,避免触发 bind/rndc。
	if err := m.st.saveSettings(Settings{ProviderKind: "mock", ProviderCreds: "tok"}); err != nil {
		t.Fatal(err)
	}
	d, _ := m.st.createDomain("example.com", 1)
	id := jstr(d.ID)

	// 注入型值必须 400。
	rec := do(r, "POST", "/domains/"+id+"/records",
		recordInput{Name: "www", Type: "A", Value: "1.2.3.4\nevil IN A 6.6.6.6", TTL: 300}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection value should 400, got %d (%s)", rec.Code, rec.Body)
	}

	// 合法 A 记录 → 200,并落库。
	rec = do(r, "POST", "/domains/"+id+"/records",
		recordInput{Name: "www", Type: "A", Value: "1.2.3.4", TTL: 300}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid record should 200, got %d (%s)", rec.Code, rec.Body)
	}
	recs, _ := m.st.listRecords(d.ID)
	if len(recs) != 1 || recs[0].Value != "1.2.3.4" {
		t.Fatalf("record not persisted: %+v", recs)
	}
}

func TestCreateRecordRollsBackOnBackendFailure(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)
	// mock provider 无凭证 → healthy 失败 → apply 失败 → 应回滚 DB。
	if err := m.st.saveSettings(Settings{ProviderKind: "mock", ProviderCreds: ""}); err != nil {
		t.Fatal(err)
	}
	d, _ := m.st.createDomain("example.com", 1)
	id := jstr(d.ID)
	rec := do(r, "POST", "/domains/"+id+"/records",
		recordInput{Name: "www", Type: "A", Value: "1.2.3.4", TTL: 300}, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("backend-unhealthy apply should 502, got %d", rec.Code)
	}
	recs, _ := m.st.listRecords(d.ID)
	if len(recs) != 0 {
		t.Fatalf("failed apply must roll back DB record, got %+v", recs)
	}
}

func TestDeleteRecordNeedsConfirm(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)
	d, _ := m.st.createDomain("example.com", 1)
	rcd, _ := m.st.createRecord(d.ID, Record{Name: "www", Type: "A", Value: "1.2.3.4", TTL: 300})
	path := "/domains/" + jstr(d.ID) + "/records/" + jstr(rcd.ID)
	rec := do(r, "DELETE", path, nil, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete record without confirm should 428, got %d", rec.Code)
	}
}

func TestSettingsCredsNeverLeak(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)
	// 写凭证。
	rec := do(r, "PUT", "/settings", Settings{ProviderKind: "mock", ProviderCreds: "super-secret-token"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put settings should 200, got %d (%s)", rec.Code, rec.Body)
	}
	// GET 不得回传凭证明文,且 creds_set=true。
	rec = do(r, "GET", "/settings", nil, nil)
	body := rec.Body.String()
	if bytes.Contains([]byte(body), []byte("super-secret-token")) {
		t.Fatalf("GET /settings leaked credentials: %s", body)
	}
	var out struct {
		CredsSet bool `json:"creds_set"`
	}
	json.Unmarshal([]byte(body), &out)
	if !out.CredsSet {
		t.Errorf("creds_set should be true after saving creds")
	}
	// 直查库:凭证列必须是密文,非明文。
	var raw string
	m.st.db.QueryRow(`SELECT provider_creds FROM dns_settings WHERE id=1`).Scan(&raw)
	if raw == "" || raw == "super-secret-token" {
		t.Fatalf("credentials stored in plaintext or missing: %q", raw)
	}
	// 解密回原文,证明可往返。
	got, err := m.st.cryp.decrypt(raw)
	if err != nil || got != "super-secret-token" {
		t.Fatalf("decrypt round-trip = %q, %v", got, err)
	}
}

func TestSettingsRequiresAdmin(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "operator", &audited)
	if rec := do(r, "GET", "/settings", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin GET settings should 403, got %d", rec.Code)
	}
	if rec := do(r, "PUT", "/settings", Settings{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin PUT settings should 403, got %d", rec.Code)
	}
}

func TestEmptyCredsKeepsOldOnUpdate(t *testing.T) {
	m, _ := newTestModule(t, "admin", new(int))
	if err := m.st.saveSettings(Settings{ProviderKind: "mock", ProviderCreds: "tok1"}); err != nil {
		t.Fatal(err)
	}
	// 二次保存空凭证,应保留旧密文。
	if err := m.st.saveSettings(Settings{ProviderKind: "mock", ProviderCreds: ""}); err != nil {
		t.Fatal(err)
	}
	eff, err := m.st.effective()
	if err != nil {
		t.Fatal(err)
	}
	if eff.ProviderCreds != "tok1" {
		t.Errorf("empty creds update should keep old, got %q", eff.ProviderCreds)
	}
}

func TestDefaultSettings(t *testing.T) {
	m, _ := newTestModule(t, "admin", new(int))
	eff, credsSet, err := m.st.masked()
	if err != nil {
		t.Fatal(err)
	}
	if eff.ProviderKind != "bind" || eff.BindZoneDir != defaultBindZoneDir || credsSet {
		t.Errorf("unexpected defaults: %+v credsSet=%v", eff, credsSet)
	}
}

func jstr(id int64) string { return strconv.FormatInt(id, 10) }
