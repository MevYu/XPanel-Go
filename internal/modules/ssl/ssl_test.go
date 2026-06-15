package ssl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockACME 记录调用并返回可配置结果,用于断言无需真实 CLI。
type mockACME struct {
	issueErr  error
	renewErr  error
	availErr  error
	issued    []IssueRequest
	renewed   []string
	writeCert []byte // 若非空,Issue/Renew 时写到 CertPath/KeyPath
	writeKey  []byte
}

func (m *mockACME) Issue(req IssueRequest) error {
	m.issued = append(m.issued, req)
	if m.issueErr != nil {
		return m.issueErr
	}
	m.materialize(req.CertPath, req.KeyPath)
	return nil
}

func (m *mockACME) Renew(domain, keyPath, certPath string) error {
	m.renewed = append(m.renewed, domain)
	if m.renewErr != nil {
		return m.renewErr
	}
	m.materialize(certPath, keyPath)
	return nil
}

func (m *mockACME) materialize(certPath, keyPath string) {
	if len(m.writeCert) > 0 {
		_ = os.MkdirAll(filepath.Dir(certPath), 0o755)
		_ = os.WriteFile(certPath, m.writeCert, 0o644)
	}
	if len(m.writeKey) > 0 {
		_ = os.MkdirAll(filepath.Dir(keyPath), 0o755)
		_ = os.WriteFile(keyPath, m.writeKey, 0o644)
	}
}

func (m *mockACME) Available() error { return m.availErr }
func (*mockACME) Name() string       { return "mock" }

func newModule(t *testing.T, acme ACME, role string, audited *int) *Module {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	m := New(st, acme, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	})
	// 把证书目录指向 t.TempDir,避免写真实系统路径。
	m.ss.setSetting(keyCertDir, t.TempDir())
	m.ss.setSetting(keyWebroot, t.TempDir())
	return m
}

func router(m *Module) chi.Router {
	r := chi.NewRouter()
	m.Routes(r)
	return r
}

// genCertPEM 生成一张自签证书 PEM(到期时间可控)与私钥 PEM。
func genCertPEM(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestMetaSwitchableCategory(t *testing.T) {
	m := newModule(t, &mockACME{}, "admin", new(int))
	meta := m.Meta()
	if meta.ID != "ssl" || meta.Category != "网站" || meta.AlwaysOn {
		t.Errorf("bad meta: %+v", meta)
	}
}

func TestHealthCheckUsesACME(t *testing.T) {
	m := newModule(t, &mockACME{availErr: errNotFound}, "admin", new(int))
	if m.HealthCheck() == nil {
		t.Error("HealthCheck must surface ACME unavailability")
	}
	m2 := newModule(t, &mockACME{}, "admin", new(int))
	if err := m2.HealthCheck(); err != nil {
		t.Errorf("HealthCheck should pass when ACME available: %v", err)
	}
}

func TestIssueHappyPath(t *testing.T) {
	cert, key := genCertPEM(t, time.Now().Add(90*24*time.Hour))
	acme := &mockACME{writeCert: cert, writeKey: key}
	audited := 0
	m := newModule(t, acme, "operator", &audited)

	body, _ := json.Marshal(issueRequest{Domains: []string{"example.com"}, Challenge: "webroot"})
	rec := do(m, "POST", "/certs", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue code = %d, body %s", rec.Code, rec.Body)
	}
	if len(acme.issued) != 1 {
		t.Fatalf("acme.Issue called %d times", len(acme.issued))
	}
	if audited != 1 {
		t.Errorf("issue must audit once, got %d", audited)
	}
	var c Cert
	json.Unmarshal(rec.Body.Bytes(), &c)
	if c.NotAfter == 0 {
		t.Error("expiry should be parsed from issued cert")
	}
	// 私钥文件应为 0600
	fi, err := os.Stat(c.KeyPath)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key perm = %o, want 600", fi.Mode().Perm())
	}
}

func TestIssueRejectsBadDomain(t *testing.T) {
	acme := &mockACME{}
	m := newModule(t, acme, "operator", new(int))
	body, _ := json.Marshal(issueRequest{Domains: []string{"evil.com; rm -rf /"}, Challenge: "webroot"})
	rec := do(m, "POST", "/certs", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad domain should 400, got %d", rec.Code)
	}
	if len(acme.issued) != 0 {
		t.Error("ACME must not be invoked for bad domain")
	}
}

func TestIssueRejectsBadChallenge(t *testing.T) {
	m := newModule(t, &mockACME{}, "operator", new(int))
	body, _ := json.Marshal(issueRequest{Domains: []string{"a.com"}, Challenge: "ftp"})
	rec := do(m, "POST", "/certs", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad challenge should 400, got %d", rec.Code)
	}
}

func TestIssueRequiresWriter(t *testing.T) {
	acme := &mockACME{}
	audited := 0
	m := newModule(t, acme, "readonly", &audited)
	body, _ := json.Marshal(issueRequest{Domains: []string{"a.com"}, Challenge: "webroot"})
	rec := do(m, "POST", "/certs", body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly issue should 403, got %d", rec.Code)
	}
	if audited != 0 || len(acme.issued) != 0 {
		t.Error("forbidden issue must not audit or call ACME")
	}
}

func TestUploadValidatesPEM(t *testing.T) {
	cert, key := genCertPEM(t, time.Now().Add(365*24*time.Hour))
	m := newModule(t, &mockACME{}, "operator", new(int))

	// 坏证书
	bad, _ := json.Marshal(uploadRequest{Domains: []string{"a.com"}, Cert: "not pem", Key: string(key)})
	if rec := do(m, "POST", "/certs/upload", bad); rec.Code != http.StatusBadRequest {
		t.Errorf("bad cert PEM should 400, got %d", rec.Code)
	}
	// 坏私钥
	bad2, _ := json.Marshal(uploadRequest{Domains: []string{"a.com"}, Cert: string(cert), Key: "nope"})
	if rec := do(m, "POST", "/certs/upload", bad2); rec.Code != http.StatusBadRequest {
		t.Errorf("bad key PEM should 400, got %d", rec.Code)
	}
	// 正常上传
	ok, _ := json.Marshal(uploadRequest{Domains: []string{"a.com"}, Cert: string(cert), Key: string(key)})
	rec := do(m, "POST", "/certs/upload", ok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload should 201, got %d body %s", rec.Code, rec.Body)
	}
	var c Cert
	json.Unmarshal(rec.Body.Bytes(), &c)
	if c.Issuer != "uploaded" || c.AutoRenew {
		t.Errorf("uploaded cert metadata wrong: %+v", c)
	}
	fi, _ := os.Stat(c.KeyPath)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("uploaded key perm = %o, want 600", fi.Mode().Perm())
	}
}

func TestRenewUpdatesExpiry(t *testing.T) {
	cert, key := genCertPEM(t, time.Now().Add(90*24*time.Hour))
	acme := &mockACME{writeCert: cert, writeKey: key}
	audited := 0
	m := newModule(t, acme, "operator", &audited)
	id, _ := m.ss.create(Cert{Domains: "example.com", CertPath: filepath.Join(t.TempDir(), "fc.pem"),
		KeyPath: filepath.Join(t.TempDir(), "k.pem"), NotAfter: 1, AutoRenew: true})

	rec := do(m, "POST", "/certs/"+itoa(id)+"/renew", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew code = %d body %s", rec.Code, rec.Body)
	}
	if len(acme.renewed) != 1 || acme.renewed[0] != "example.com" {
		t.Errorf("renew should call ACME for example.com, got %v", acme.renewed)
	}
	c, _ := m.ss.get(id)
	if c.NotAfter <= 1 || c.LastRenewAt == nil {
		t.Errorf("renew should refresh expiry, got %+v", c)
	}
}

func TestDeleteRequiresAdmin(t *testing.T) {
	m := newModule(t, &mockACME{}, "operator", new(int))
	id, _ := m.ss.create(Cert{Domains: "a.com", CertPath: "/x", KeyPath: "/y"})
	if rec := do(m, "DELETE", "/certs/"+itoa(id), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("operator delete should 403, got %d", rec.Code)
	}

	mAdmin := newModule(t, &mockACME{}, "admin", new(int))
	cp := filepath.Join(t.TempDir(), "fc.pem")
	kp := filepath.Join(t.TempDir(), "k.pem")
	os.WriteFile(cp, []byte("x"), 0o600)
	os.WriteFile(kp, []byte("x"), 0o600)
	id2, _ := mAdmin.ss.create(Cert{Domains: "a.com", CertPath: cp, KeyPath: kp})
	if rec := do(mAdmin, "DELETE", "/certs/"+itoa(id2), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("admin delete should 204, got %d", rec.Code)
	}
	if _, err := os.Stat(kp); !os.IsNotExist(err) {
		t.Error("admin delete should remove key file")
	}
}

func TestAutoRenewToggle(t *testing.T) {
	m := newModule(t, &mockACME{}, "operator", new(int))
	id, _ := m.ss.create(Cert{Domains: "a.com", CertPath: "/x", KeyPath: "/y", AutoRenew: true})
	if rec := do(m, "POST", "/certs/"+itoa(id)+"/auto/off", nil); rec.Code != http.StatusOK {
		t.Fatalf("toggle off code = %d", rec.Code)
	}
	c, _ := m.ss.get(id)
	if c.AutoRenew {
		t.Error("auto-renew should be off")
	}
}

func TestSettingsRBACAndPersist(t *testing.T) {
	// 非 admin 读写都拒绝
	op := newModule(t, &mockACME{}, "operator", new(int))
	if rec := do(op, "GET", "/settings", nil); rec.Code != http.StatusForbidden {
		t.Errorf("operator GET settings should 403, got %d", rec.Code)
	}
	if rec := do(op, "PUT", "/settings", []byte(`{"cert_dir":"/x"}`)); rec.Code != http.StatusForbidden {
		t.Errorf("operator PUT settings should 403, got %d", rec.Code)
	}

	admin := newModule(t, &mockACME{}, "admin", new(int))
	// 非法路径拒绝
	if rec := do(admin, "PUT", "/settings", []byte(`{"cert_dir":"relative/path"}`)); rec.Code != http.StatusBadRequest {
		t.Errorf("relative path should 400, got %d", rec.Code)
	}
	if rec := do(admin, "PUT", "/settings", []byte(`{"webroot":"/etc/../x; rm"}`)); rec.Code != http.StatusBadRequest {
		t.Errorf("injection path should 400, got %d", rec.Code)
	}
	// 合法更新
	rec := do(admin, "PUT", "/settings", []byte(`{"cert_dir":"/custom/cert","webroot":"/www"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid settings PUT should 200, got %d body %s", rec.Code, rec.Body)
	}
	var resp settingsResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.CertDir != "/custom/cert" || resp.Webroot != "/www" {
		t.Errorf("settings not persisted: %+v", resp)
	}
}

func TestRenewDueBatch(t *testing.T) {
	cert, key := genCertPEM(t, time.Now().Add(90*24*time.Hour))
	acme := &mockACME{writeCert: cert, writeKey: key}
	m := newModule(t, acme, "operator", new(int))
	dir := t.TempDir()
	// due: auto on, expires soon
	m.ss.create(Cert{Domains: "due.com", CertPath: filepath.Join(dir, "d.pem"),
		KeyPath: filepath.Join(dir, "dk.pem"), NotAfter: nowUnix() + 100, AutoRenew: true})
	// not due: far future
	m.ss.create(Cert{Domains: "far.com", CertPath: filepath.Join(dir, "f.pem"),
		KeyPath: filepath.Join(dir, "fk.pem"), NotAfter: nowUnix() + renewWindow + 100000, AutoRenew: true})

	rec := do(m, "POST", "/renew-due", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew-due code = %d", rec.Code)
	}
	var res map[string]int
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res["renewed"] != 1 || res["failed"] != 0 {
		t.Errorf("expected 1 renewed 0 failed, got %v", res)
	}
	if len(acme.renewed) != 1 || acme.renewed[0] != "due.com" {
		t.Errorf("only due.com should renew, got %v", acme.renewed)
	}
}

func TestIssueFailureMasksAndAudits(t *testing.T) {
	acme := &mockACME{issueErr: errNotFound}
	audited := 0
	m := newModule(t, acme, "operator", &audited)
	body, _ := json.Marshal(issueRequest{Domains: []string{"a.com"}, Challenge: "standalone"})
	rec := do(m, "POST", "/certs", body)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("issue failure should 500, got %d", rec.Code)
	}
	if rec.Body.String() != "issue failed\n" {
		t.Errorf("failure body must be generic, got %q", rec.Body.String())
	}
	if audited != 1 {
		t.Errorf("failed issue must still audit, got %d", audited)
	}
}

// ---- helpers ----

func do(m *Module, method, path string, body []byte) *httptest.ResponseRecorder {
	r := router(m)
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func itoa(i int64) string {
	return strconv.FormatInt(i, 10)
}
