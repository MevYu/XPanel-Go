package sites

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// acmeChallenge 是一条 HTTP-01 应答:在 <token> 文件里放 <keyAuth> 内容。
type acmeChallenge struct{ Token, KeyAuth string }

// acmeIssuer 抽象证书签发,便于单测注入 mock(测试绝不触网)。
type acmeIssuer interface {
	// Issue 对 domains 走完整 HTTP-01 订单流程:每个挑战经 writeChallenge 放置应答文件、
	// 完成后经 removeChallenge 清理。返回 PEM 证书链与 PEM 私钥。
	Issue(ctx context.Context, email string, domains []string,
		writeChallenge func(token, keyAuth string) error, removeChallenge func(token string)) (certPEM, keyPEM string, err error)
}

// emailRe 是宽松邮箱校验:用于 ACME 账户联系邮箱。
var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$`)

func validEmail(s string) bool {
	return len(s) <= 254 && emailRe.MatchString(s)
}

// realACME 用 golang.org/x/crypto/acme 对接 Let's Encrypt。测试从不触达本实现。
type realACME struct{}

func newRealACME() *realACME { return &realACME{} }

// Issue 注册账户 → 下单 → 对每个授权置 HTTP-01 应答 → 接受 → 等待 → CSR finalize → 取证书。
func (realACME) Issue(ctx context.Context, email string, domains []string,
	writeChallenge func(token, keyAuth string) error, removeChallenge func(token string)) (string, string, error) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: acme.LetsEncryptURL}
	if _, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + email}}, acme.AcceptTOS); err != nil {
		return "", "", fmt.Errorf("acme register: %w", err)
	}

	ids := make([]acme.AuthzID, len(domains))
	for i, d := range domains {
		ids[i] = acme.AuthzID{Type: "dns", Value: d}
	}
	order, err := client.AuthorizeOrder(ctx, ids)
	if err != nil {
		return "", "", fmt.Errorf("acme order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return "", "", err
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return "", "", fmt.Errorf("no http-01 challenge for %s", authz.Identifier.Value)
		}
		keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return "", "", err
		}
		if err := writeChallenge(chal.Token, keyAuth); err != nil {
			return "", "", fmt.Errorf("place challenge: %w", err)
		}
		_, err = client.Accept(ctx, chal)
		if err != nil {
			removeChallenge(chal.Token)
			return "", "", err
		}
		_, err = client.WaitAuthorization(ctx, authzURL)
		removeChallenge(chal.Token)
		if err != nil {
			return "", "", fmt.Errorf("authorization failed: %w", err)
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, certKey)
	if err != nil {
		return "", "", err
	}
	ders, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return "", "", fmt.Errorf("acme finalize: %w", err)
	}

	var certBuf strings.Builder
	for _, der := range ders {
		if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return "", "", err
		}
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certBuf.String(), string(keyPEM), nil
}

// certNotAfter 解析 PEM 证书链中首张证书的 NotAfter。
func certNotAfter(certPEM string) (int64, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return 0, fmt.Errorf("no PEM certificate found")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, err
	}
	return crt.NotAfter.Unix(), nil
}

// handleACMEIssue 经 Let's Encrypt HTTP-01 为站点签发证书并落库。operator+。
func (m *Module) handleACMEIssue(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadForWrite(w, r)
	if !ok {
		return
	}
	var req struct {
		Email   string   `json:"email"`
		Domains []string `json:"domains"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if !validEmail(req.Email) {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}
	if len(req.Domains) == 0 || len(req.Domains) > 16 {
		http.Error(w, "domains must be 1..16", http.StatusBadRequest)
		return
	}
	bound := make(map[string]bool, len(site.DomainBindings))
	for _, b := range site.DomainBindings {
		bound[b.Domain] = true
	}
	domains := make([]string, 0, len(req.Domains))
	for _, d := range req.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !validDomain(d) {
			http.Error(w, "invalid domain "+d, http.StatusBadRequest)
			return
		}
		if !bound[d] {
			http.Error(w, "domain not bound to site: "+d, http.StatusBadRequest)
			return
		}
		domains = append(domains, d)
	}

	set, ok := m.loadSettings(w)
	if !ok {
		return
	}
	webroot := site.RootDir
	if webroot == "" {
		wr, err := safeWebRoot(set.WebRoot, site.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		webroot = wr
	}
	ng := m.newNginx(set.ConfDir)

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	certPEM, keyPEM, err := m.newIssuer().Issue(ctx, req.Email, domains,
		func(token, keyAuth string) error { return ng.WriteChallenge(webroot, token, keyAuth) },
		func(token string) { _ = ng.RemoveChallenge(webroot, token) })
	if err != nil {
		log.Printf("sites: acme issue %q failed: %v", site.Name, err)
		http.Error(w, "acme issuance failed", http.StatusBadGateway)
		return
	}

	certPath, keyPath, err := ng.WriteCert(site.Name, certPEM, keyPEM)
	if err != nil {
		log.Printf("sites: acme write cert %q failed: %v", site.Name, err)
		http.Error(w, "cert write failed", http.StatusInternalServerError)
		return
	}
	expiresAt, err := certNotAfter(certPEM)
	if err != nil {
		log.Printf("sites: acme parse cert %q failed: %v", site.Name, err)
		http.Error(w, "issued cert is unparseable", http.StatusBadGateway)
		return
	}
	site.SSL = SSL{
		Enabled:     true,
		CertPath:    certPath,
		KeyPath:     keyPath,
		ForceHTTPS:  site.SSL.ForceHTTPS,
		HSTS:        site.SSL.HSTS,
		ACMEEmail:   req.Email,
		ACMEDomains: domains,
		ExpiresAt:   expiresAt,
	}
	m.applySite(w, r, site, "sites.ssl.acme", site.Name+" "+strings.Join(domains, ","))
}
