package sites

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// selfSignedPEM 生成一张自签证书 + 私钥(PEM),NotAfter 由 validFor 决定。测试专用,绝不触网。
func selfSignedPEM(t *testing.T, cn string, validFor time.Duration) (certPEM, keyPEM string, notAfter int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	na := time.Now().Add(validFor)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     na,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	kp := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(cp), string(kp), na.Unix()
}

// mockIssuer 模拟 ACME 签发:记录调用、演练挑战放置+清理、返回自签证书。绝不触网。
type mockIssuer struct {
	calls       int
	lastEmail   string
	lastDomains []string
	certPEM     string
	keyPEM      string
}

func (mi *mockIssuer) Issue(_ context.Context, email string, domains []string,
	writeChallenge func(token, keyAuth string) error, removeChallenge func(token string)) (string, string, error) {
	mi.calls++
	mi.lastEmail = email
	mi.lastDomains = domains
	if err := writeChallenge("tok", "keyauth"); err != nil {
		return "", "", err
	}
	removeChallenge("tok")
	return mi.certPEM, mi.keyPEM, nil
}

func TestACMEIssueSuccess(t *testing.T) {
	ng := newMockNginx()
	m, audited := newTestModule(t, "operator", ng)
	id := seedSite(t, m)

	certPEM, keyPEM, notAfter := selfSignedPEM(t, "example.com", 60*24*time.Hour)
	mi := &mockIssuer{certPEM: certPEM, keyPEM: keyPEM}
	m.newIssuer = func() acmeIssuer { return mi }
	*audited = 0

	rec := do(m, "POST", "/sites/"+itoa(id)+"/ssl/acme",
		map[string]any{"email": "admin@example.com", "domains": []string{"example.com"}}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("acme issue = %d (%s)", rec.Code, rec.Body.String())
	}

	if len(ng.chalWrites) == 0 {
		t.Error("issuer must place challenge via WriteChallenge")
	}
	if len(ng.chalRemd) == 0 {
		t.Error("issuer must clean challenge via RemoveChallenge")
	}
	if _, ok := ng.configs["cert:example.com"]; !ok {
		t.Error("cert must be written via WriteCert")
	}
	if ng.reloads == 0 {
		t.Error("nginx must reload after issuance")
	}
	if mi.lastEmail != "admin@example.com" || len(mi.lastDomains) != 1 {
		t.Errorf("issuer got wrong args: %q %v", mi.lastEmail, mi.lastDomains)
	}
	if *audited != 1 {
		t.Errorf("acme issue must audit once, got %d", *audited)
	}

	var s Site
	json.Unmarshal(rec.Body.Bytes(), &s)
	if !s.SSL.Enabled || s.SSL.CertPath == "" || s.SSL.KeyPath == "" {
		t.Errorf("SSL not enabled with cert paths: %+v", s.SSL)
	}
	if s.SSL.ACMEEmail != "admin@example.com" {
		t.Errorf("acme_email not persisted: %q", s.SSL.ACMEEmail)
	}
	if s.SSL.ExpiresAt != notAfter {
		t.Errorf("expires_at = %d, want %d", s.SSL.ExpiresAt, notAfter)
	}
}

func TestACMEIssueValidation(t *testing.T) {
	cert, key, _ := selfSignedPEM(t, "example.com", 60*24*time.Hour)
	mkIssuer := func() acmeIssuer { return &mockIssuer{certPEM: cert, keyPEM: key} }

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"unbound domain", map[string]any{"email": "a@b.com", "domains": []string{"other.com"}}, http.StatusBadRequest},
		{"bad email", map[string]any{"email": "notanemail", "domains": []string{"example.com"}}, http.StatusBadRequest},
		{"empty domains", map[string]any{"email": "a@b.com", "domains": []string{}}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ng := newMockNginx()
			m, _ := newTestModule(t, "operator", ng)
			m.newIssuer = mkIssuer
			id := seedSite(t, m)
			rec := do(m, "POST", "/sites/"+itoa(id)+"/ssl/acme", tc.body, nil)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	// readonly 角色:requireWriter 先于 loadSite 拦截,无需真实站点。
	ng := newMockNginx()
	m, _ := newTestModule(t, "readonly", ng)
	m.newIssuer = mkIssuer
	rec := do(m, "POST", "/sites/1/ssl/acme",
		map[string]any{"email": "a@b.com", "domains": []string{"example.com"}}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly should 403, got %d", rec.Code)
	}
}
