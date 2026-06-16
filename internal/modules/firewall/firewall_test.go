package firewall

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// mockBackend 记录调用并返回可控结果,供 handler 测试断言后端被(或不被)调用。
type mockBackend struct {
	name      string
	portCalls []struct {
		rule PortRule
		add  bool
	}
	ipCalls []struct {
		rule IPRule
		add  bool
	}
	pingCalls   []bool
	enableCalls []bool
	status      Status
	pingErr     error
	applyErr    error
}

func (b *mockBackend) Name() string { return b.name }

func (b *mockBackend) Status() (Status, error) { return b.status, nil }

func (b *mockBackend) ListPortRules() ([]PortRule, error) {
	return []PortRule{{Action: "allow", Port: "80", Proto: "tcp"}}, nil
}

func (b *mockBackend) ApplyPortRule(r PortRule, add bool) (string, error) {
	b.portCalls = append(b.portCalls, struct {
		rule PortRule
		add  bool
	}{r, add})
	return "ok", b.applyErr
}

func (b *mockBackend) ApplyIPRule(r IPRule, add bool) (string, error) {
	b.ipCalls = append(b.ipCalls, struct {
		rule IPRule
		add  bool
	}{r, add})
	return "ok", b.applyErr
}

func (b *mockBackend) SetPing(allow bool) (string, error) {
	b.pingCalls = append(b.pingCalls, allow)
	return "ok", b.pingErr
}

func (b *mockBackend) SetEnabled(enable bool) (string, error) {
	b.enableCalls = append(b.enableCalls, enable)
	return "ok", nil
}

func fakeDeps(role string, audited *int) Deps {
	return Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(userID *int64, action, detail, ip string) { *audited++ },
	}
}

// newModuleWith 构造注入了 mock 后端的模块。be==nil 时模拟"无后端"。
func newModuleWith(role string, audited *int, be *mockBackend) *Module {
	m := New(fakeDeps(role, audited))
	m.newBackend = func(runner) Backend {
		if be == nil {
			return nil
		}
		return be
	}
	return m
}

func newRouter(role string, audited *int) chi.Router {
	return routerWith(newModuleWith(role, audited, &mockBackend{name: "ufw"}))
}

func routerWith(m *Module) chi.Router {
	r := chi.NewRouter()
	m.Routes(r)
	return r
}

func do(r chi.Router, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	r.ServeHTTP(rec, req)
	return rec
}

func TestMetaSwitchable(t *testing.T) {
	m := New(fakeDeps("admin", new(int)))
	meta := m.Meta()
	if meta.ID != "firewall" || meta.AlwaysOn {
		t.Errorf("firewall must be id=firewall, not AlwaysOn, got %+v", meta)
	}
	if meta.Category != "安全" {
		t.Errorf("category must be 安全, got %q", meta.Category)
	}
}

func TestNav(t *testing.T) {
	nav := New(fakeDeps("admin", new(int))).Nav()
	if len(nav) != 1 || nav[0].Path != "/firewall" {
		t.Errorf("nav must expose /firewall, got %+v", nav)
	}
}

func TestRuleChangeRequiresAdmin(t *testing.T) {
	for _, role := range []string{"readonly", "operator"} {
		audited := 0
		be := &mockBackend{name: "ufw"}
		r := routerWith(newModuleWith(role, &audited, be))
		rec := do(r, "POST", "/rules", `{"action":"allow","port":"80","proto":"tcp"}`, nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("role %s rule change should be 403, got %d", role, rec.Code)
		}
		if audited != 0 {
			t.Errorf("role %s forbidden request must not audit, got %d", role, audited)
		}
		if len(be.portCalls) != 0 {
			t.Errorf("forbidden request must not reach backend")
		}
	}
}

func TestRuleChangeRejectsInvalidPort(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/rules", `{"action":"allow","port":"0","proto":"tcp"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid port must 400 before exec, got %d", rec.Code)
	}
	if audited != 0 || len(be.portCalls) != 0 {
		t.Errorf("rejected-before-exec must not audit/exec")
	}
}

func TestRuleChangeRejectsInjectionSource(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/rules", `{"action":"allow","port":"80","proto":"tcp","source":"1.2.3.4; rm -rf /"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("injection source must 400, got %d", rec.Code)
	}
	if len(be.portCalls) != 0 {
		t.Errorf("injection must not reach backend")
	}
}

func TestRuleChangeRejectsBadProto(t *testing.T) {
	audited := 0
	r := routerWith(newModuleWith("admin", &audited, &mockBackend{name: "ufw"}))
	rec := do(r, "POST", "/rules", `{"action":"allow","port":"80","proto":"icmp"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad proto must 400, got %d", rec.Code)
	}
}

func TestRuleChangeRejectsBadComment(t *testing.T) {
	audited := 0
	r := routerWith(newModuleWith("admin", &audited, &mockBackend{name: "ufw"}))
	rec := do(r, "POST", "/rules", `{"action":"allow","port":"80","proto":"tcp","comment":"a\nb"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("control-char comment must 400, got %d", rec.Code)
	}
}

func TestAddPortRangeRuleReachesBackend(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/rules", `{"action":"allow","port":"8000-9000","proto":"tcp","source":"10.0.0.0/8","comment":"web"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid range rule should 200, got %d", rec.Code)
	}
	if len(be.portCalls) != 1 || !be.portCalls[0].add || be.portCalls[0].rule.Port != "8000-9000" {
		t.Errorf("backend should receive add port-range rule, got %+v", be.portCalls)
	}
	if audited != 1 {
		t.Errorf("successful change must audit once, got %d", audited)
	}
}

func TestDeleteRuleRequiresConfirm(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "DELETE", "/rules", `{"action":"allow","port":"80","proto":"tcp"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("delete without confirm must be 428, got %d", rec.Code)
	}
	if audited != 0 || len(be.portCalls) != 0 {
		t.Errorf("unconfirmed delete must not audit/exec")
	}
}

func TestDeleteRuleWithConfirm(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "DELETE", "/rules", `{"action":"allow","port":"80","proto":"tcp"}`, map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed delete should 200, got %d", rec.Code)
	}
	if len(be.portCalls) != 1 || be.portCalls[0].add {
		t.Errorf("delete should call backend with add=false, got %+v", be.portCalls)
	}
}

func TestBlockIPRequiresConfirm(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/ip", `{"action":"block","ip":"1.2.3.4"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("block without confirm must be 428, got %d", rec.Code)
	}
	if len(be.ipCalls) != 0 {
		t.Errorf("unconfirmed block must not reach backend")
	}
}

func TestBlockIPWithConfirm(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/ip", `{"action":"block","ip":"1.2.3.4"}`, map[string]string{"X-Confirm-Danger": "x"})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed block should 200, got %d", rec.Code)
	}
	if len(be.ipCalls) != 1 || be.ipCalls[0].rule.Action != IPBlock {
		t.Errorf("block should reach backend, got %+v", be.ipCalls)
	}
}

func TestTrustIPNoConfirmNeeded(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/ip", `{"action":"trust","ip":"10.0.0.0/8"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("trust should not need confirm, got %d", rec.Code)
	}
	if len(be.ipCalls) != 1 || be.ipCalls[0].rule.Action != IPTrust {
		t.Errorf("trust should reach backend, got %+v", be.ipCalls)
	}
}

func TestIPRuleRejectsBadIP(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/ip", `{"action":"trust","ip":"not-an-ip"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad ip must 400, got %d", rec.Code)
	}
	if len(be.ipCalls) != 0 {
		t.Errorf("bad ip must not reach backend")
	}
}

func TestIPRuleRequiresAdmin(t *testing.T) {
	audited := 0
	r := routerWith(newModuleWith("operator", &audited, &mockBackend{name: "ufw"}))
	rec := do(r, "POST", "/ip", `{"action":"trust","ip":"10.0.0.1"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator ip change must be 403, got %d", rec.Code)
	}
}

func TestPingAllow(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "firewalld"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/ping", `{"allow":true}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("allow ping should 200, got %d", rec.Code)
	}
	if len(be.pingCalls) != 1 || !be.pingCalls[0] {
		t.Errorf("ping allow should reach backend true, got %+v", be.pingCalls)
	}
}

func TestPingDenyRequiresConfirm(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "firewalld"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/ping", `{"allow":false}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("deny ping without confirm must be 428, got %d", rec.Code)
	}
	if len(be.pingCalls) != 0 {
		t.Errorf("unconfirmed ping-deny must not reach backend")
	}
}

func TestPingUnsupportedBackend(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw", pingErr: errPingUnsupported}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/ping", `{"allow":true}`, nil)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("unsupported ping toggle must be 501, got %d", rec.Code)
	}
}

func TestDisableRequiresConfirm(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/disable", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("disable without confirm must be 428, got %d", rec.Code)
	}
	if len(be.enableCalls) != 0 {
		t.Errorf("unconfirmed disable must not reach backend")
	}
}

func TestDisableRequiresAdmin(t *testing.T) {
	audited := 0
	r := routerWith(newModuleWith("operator", &audited, &mockBackend{name: "ufw"}))
	rec := do(r, "POST", "/disable", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator disable must be 403, got %d", rec.Code)
	}
}

func TestEnableReachesBackend(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw"}
	r := routerWith(newModuleWith("admin", &audited, be))
	rec := do(r, "POST", "/enable", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable should 200, got %d", rec.Code)
	}
	if len(be.enableCalls) != 1 || !be.enableCalls[0] {
		t.Errorf("enable should reach backend true, got %+v", be.enableCalls)
	}
}

func TestListIsReadable(t *testing.T) {
	audited := 0
	r := routerWith(newModuleWith("readonly", &audited, &mockBackend{name: "ufw"}))
	rec := do(r, "GET", "/rules", "", nil)
	if rec.Code == http.StatusForbidden {
		t.Errorf("list must not require admin, got 403")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("list should 200 with backend, got %d", rec.Code)
	}
}

func TestStatusReportsBackendAndSSH(t *testing.T) {
	audited := 0
	be := &mockBackend{name: "ufw", status: Status{Backend: "ufw", Running: true, RuleCount: 3}}
	m := newModuleWith("readonly", &audited, be)
	m.sshConfig = "testdata/sshd_config" // Port 2222
	r := routerWith(m)
	rec := do(r, "GET", "/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status should 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"backend":"ufw"`) || !strings.Contains(body, `"ruleCount":3`) {
		t.Errorf("status body missing fields: %s", body)
	}
	if !strings.Contains(body, `"sshPort":2222`) {
		t.Errorf("status should reflect configured sshPort 2222: %s", body)
	}
}

func TestBackendEndpointNoBackend(t *testing.T) {
	audited := 0
	r := routerWith(newModuleWith("readonly", &audited, nil))
	rec := do(r, "GET", "/backend", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"backend":""`) {
		t.Errorf("no-backend should report empty backend, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestSSHReadonly(t *testing.T) {
	audited := 0
	m := newModuleWith("readonly", &audited, &mockBackend{name: "ufw"})
	m.sshConfig = "/nonexistent/sshd_config"
	r := routerWith(m)
	rec := do(r, "GET", "/ssh", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("ssh should 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"readonly":true`) {
		t.Errorf("ssh must advertise readonly, got %s", rec.Body.String())
	}
}
