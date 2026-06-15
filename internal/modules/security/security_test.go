package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// ---- mocks ----

type mockSSH struct {
	dirs    map[string]string
	setKey  string
	setVal  string
	reloads int
}

func (m *mockSSH) ReadDirectives(string) (map[string]string, error) { return m.dirs, nil }
func (m *mockSSH) SetDirective(_, key, value string) (string, error) {
	if err := ValidateSSHDirective(key, value); err != nil {
		return "", err
	}
	m.setKey, m.setVal = key, value
	return "/etc/ssh/sshd_config.xpanel.bak", nil
}
func (m *mockSSH) Validate(string) error { return nil }
func (m *mockSSH) Reload() error         { m.reloads++; return nil }
func (m *mockSSH) Available() error      { return nil }

type mockF2b struct {
	unbanned [][2]string
	jailOps  [][2]string
}

func (m *mockF2b) Status(string) (string, error)   { return "ok", nil }
func (m *mockF2b) Banned(string) ([]string, error) { return []string{"1.2.3.4"}, nil }
func (m *mockF2b) Unban(jail, ip string) error {
	m.unbanned = append(m.unbanned, [2]string{jail, ip})
	return nil
}
func (m *mockF2b) SetJail(jail string, enable bool) error {
	op := "stop"
	if enable {
		op = "start"
	}
	m.jailOps = append(m.jailOps, [2]string{jail, op})
	return nil
}
func (m *mockF2b) Available() error { return nil }

type mockLog struct{}

func (mockLog) Recent(failed bool, limit int) ([]LoginEntry, error) {
	return []LoginEntry{{User: "root", IP: "1.2.3.4", Failed: failed}}, nil
}

// ---- test harness ----

func newTestModule(t *testing.T, role string, audited *int) (*Module, chi.Router) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	deps := Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	}
	m := New(st, &mockSSH{dirs: map[string]string{"Port": "22"}}, &mockF2b{}, mockLog{}, deps)
	r := chi.NewRouter()
	m.Routes(r)
	return m, r
}

func do(r chi.Router, method, path, body string, confirm bool) *httptest.ResponseRecorder {
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	if confirm {
		req.Header.Set("X-Confirm-Danger", "yes")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestMetaSwitchable(t *testing.T) {
	m, _ := newTestModule(t, "admin", new(int))
	if m.Meta().ID != "security" || m.Meta().AlwaysOn {
		t.Errorf("must be id=security, not AlwaysOn, got %+v", m.Meta())
	}
	if m.Meta().Category != "安全" {
		t.Errorf("category must be 安全, got %q", m.Meta().Category)
	}
}

func TestNonAdminForbiddenEverywhere(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "operator", &audited)
	reqs := []struct {
		method, path, body string
	}{
		{"GET", "/settings", ""},
		{"PUT", "/sshd", `{"key":"Port","value":"2222"}`},
		{"GET", "/keys", ""},
		{"POST", "/fail2ban/unban", `{"jail":"sshd","ip":"1.2.3.4"}`},
		{"GET", "/logins", ""},
	}
	for _, rq := range reqs {
		rec := do(r, rq.method, rq.path, rq.body, true)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s non-admin should be 403, got %d", rq.method, rq.path, rec.Code)
		}
	}
	if audited != 0 {
		t.Errorf("forbidden requests must not audit, got %d", audited)
	}
}

func TestSSHDSetRejectsNonWhitelistKey(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "PUT", "/sshd", `{"key":"AllowUsers","value":"root"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-whitelist key must 400, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("rejected directive must not audit, got %d", audited)
	}
}

func TestSSHDSetDangerKeyRequiresConfirm(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	// 改 Port 是危险操作:无确认头 -> 428。
	rec := do(r, "PUT", "/sshd", `{"key":"Port","value":"2222"}`, false)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("danger directive without confirm must 428, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("unconfirmed danger must not audit, got %d", audited)
	}
	// 带确认头 -> 成功并审计。
	rec = do(r, "PUT", "/sshd", `{"key":"Port","value":"2222"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed danger directive must 200, got %d (%s)", rec.Code, rec.Body)
	}
	if audited != 1 {
		t.Errorf("confirmed directive must audit once, got %d", audited)
	}
}

func TestSSHDSetSafeKeyNoConfirmNeeded(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "PUT", "/sshd", `{"key":"MaxAuthTries","value":"3"}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("safe directive must 200 without confirm, got %d (%s)", rec.Code, rec.Body)
	}
}

func TestKeysAddInvalidRejected(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "POST", "/keys", `{"public_key":"garbage notakey"}`, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid public key must 400, got %d", rec.Code)
	}
	if audited != 0 {
		t.Errorf("rejected key must not audit, got %d", audited)
	}
}

func TestF2bUnbanRequiresConfirmAndValidIP(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)
	mock := m.f2b.(*mockF2b)

	// 无确认头 -> 428。
	rec := do(r, "POST", "/fail2ban/unban", `{"jail":"sshd","ip":"1.2.3.4"}`, false)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("unban without confirm must 428, got %d", rec.Code)
	}
	// 非法 IP -> 400。
	rec = do(r, "POST", "/fail2ban/unban", `{"jail":"sshd","ip":"notanip"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid ip must 400, got %d", rec.Code)
	}
	// 合法 + 确认 -> 200 且调用 mock。
	rec = do(r, "POST", "/fail2ban/unban", `{"jail":"sshd","ip":"1.2.3.4"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed unban must 200, got %d", rec.Code)
	}
	if len(mock.unbanned) != 1 {
		t.Errorf("expected 1 unban call, got %d", len(mock.unbanned))
	}
}

func TestF2bJailStopRequiresConfirm(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)
	mock := m.f2b.(*mockF2b)

	// 启用 jail 不危险,无需确认。
	rec := do(r, "POST", "/fail2ban/jail", `{"jail":"sshd","enable":true}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("jail start must 200 without confirm, got %d", rec.Code)
	}
	// 停用 jail 危险,无确认 -> 428。
	rec = do(r, "POST", "/fail2ban/jail", `{"jail":"sshd","enable":false}`, false)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("jail stop without confirm must 428, got %d", rec.Code)
	}
	// 停用带确认 -> 200。
	rec = do(r, "POST", "/fail2ban/jail", `{"jail":"sshd","enable":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed jail stop must 200, got %d", rec.Code)
	}
	if len(mock.jailOps) != 2 {
		t.Errorf("expected 2 jail ops, got %v", mock.jailOps)
	}
}

func TestF2bBannedRejectsBadJail(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "GET", "/fail2ban/banned?jail=ssh%2Frm", "", false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad jail name must 400, got %d", rec.Code)
	}
}

func TestSettingsPutRejectsRelativePath(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	body := `{"sshd_config_path":"etc/ssh/sshd_config","fail2ban_config_dir":"/x","authorized_keys":"/y"}`
	rec := do(r, "PUT", "/settings", body, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("relative path must 400, got %d", rec.Code)
	}
}

func TestSettingsDefaultsSeeded(t *testing.T) {
	audited := 0
	m, _ := newTestModule(t, "admin", &audited)
	st, err := m.st.getSettings()
	if err != nil {
		t.Fatal(err)
	}
	if st.SSHDConfigPath != "/etc/ssh/sshd_config" {
		t.Errorf("default sshd path wrong: %q", st.SSHDConfigPath)
	}
	if st.AuthorizedKeys != "/root/.ssh/authorized_keys" {
		t.Errorf("default authorized_keys wrong: %q", st.AuthorizedKeys)
	}
	if st.Fail2banConfigDir != "/etc/fail2ban/jail.d" {
		t.Errorf("default fail2ban dir wrong: %q", st.Fail2banConfigDir)
	}
}

func TestSSHDReloadValidatesFirst(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)
	mock := m.ssh.(*mockSSH)
	rec := do(r, "POST", "/sshd/reload", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload must 200, got %d", rec.Code)
	}
	if mock.reloads != 1 {
		t.Errorf("expected 1 reload, got %d", mock.reloads)
	}
}

// jail 名以 "-" 开头会被 fail2ban-client 当 flag(参数注入),必须拒绝。
func TestValidJailNameRejectsLeadingDash(t *testing.T) {
	rejected := []string{"--help", "-h", "--version", "-jail", "j ail", "j;ls", "j/etc", "j$x"}
	for _, s := range rejected {
		if validJailName(s) {
			t.Errorf("validJailName(%q) = true, want false", s)
		}
	}
	accepted := []string{"", "sshd", "nginx-http-auth", "jail_1", "Abc123", "_priv"}
	for _, s := range accepted {
		if !validJailName(s) {
			t.Errorf("validJailName(%q) = false, want true", s)
		}
	}
	if validJailName(strings.Repeat("a", 65)) {
		t.Error("validJailName must reject names longer than 64")
	}
}
