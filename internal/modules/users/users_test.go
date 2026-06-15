package users

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/pquerna/otp/totp"
)

func itoa(i int64) string { return strconv.FormatInt(i, 10) }
func timeNow() time.Time  { return time.Now() }

// testModule 用可变 principal 构造模块,便于按角色/用户切换。
type testModule struct {
	m       *Module
	uid     int64
	role    string
	audited int
}

func newTestModule(t *testing.T) *testModule {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	tm := &testModule{uid: 1, role: "admin"}
	tm.m = New(st, "host-secret", Deps{
		Principal: func(*http.Request) (int64, string) { return tm.uid, tm.role },
		Audit:     func(*int64, string, string, string) { tm.audited++ },
	})
	return tm
}

func (tm *testModule) do(method, path string, body any) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	tm.m.Routes(r)
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestMetaSwitchableSecurity(t *testing.T) {
	tm := newTestModule(t)
	meta := tm.m.Meta()
	if meta.ID != "users" || meta.Name != "用户" || meta.Category != "安全" || meta.AlwaysOn {
		t.Fatalf("unexpected meta: %+v", meta)
	}
}

func TestNav(t *testing.T) {
	tm := newTestModule(t)
	nav := tm.m.Nav()
	if len(nav) != 1 || nav[0].Path != "/users" {
		t.Fatalf("unexpected nav: %+v", nav)
	}
}

// --- RBAC ---

func TestUserMgmtRequiresAdmin(t *testing.T) {
	tm := newTestModule(t)
	tm.role = "operator"
	cases := []struct {
		method, path string
		body         any
	}{
		{"GET", "/users", nil},
		{"POST", "/users", createUserRequest{Username: "x", Password: "password1", Role: "operator"}},
		{"DELETE", "/users/2", nil},
		{"PUT", "/users/2/role", roleRequest{Role: "admin"}},
		{"POST", "/users/2/reset-password", passwordRequest{Password: "password1"}},
		{"GET", "/settings", nil},
		{"PUT", "/settings", settingsBody{TOTPIssuer: "X"}},
	}
	for _, c := range cases {
		rec := tm.do(c.method, c.path, c.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: want 403 for operator, got %d", c.method, c.path, rec.Code)
		}
	}
	if tm.audited != 0 {
		t.Fatalf("forbidden requests must not audit, got %d", tm.audited)
	}
}

func TestCreateUserFlow(t *testing.T) {
	tm := newTestModule(t)
	rec := tm.do("POST", "/users", createUserRequest{Username: "newbie", Password: "password1", Role: "operator"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body)
	}
	var info UserInfo
	json.Unmarshal(rec.Body.Bytes(), &info)
	if info.Username != "newbie" || info.Role != "operator" || info.ID == 0 {
		t.Fatalf("unexpected response: %+v", info)
	}
	if tm.audited != 1 {
		t.Fatalf("create should audit once, got %d", tm.audited)
	}
	// 重复用户名 409。
	rec = tm.do("POST", "/users", createUserRequest{Username: "newbie", Password: "password1", Role: "operator"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate should 409, got %d", rec.Code)
	}
}

func TestCreateUserValidation(t *testing.T) {
	tm := newTestModule(t)
	bad := []createUserRequest{
		{Username: "ab", Password: "password1", Role: "operator"},       // too short
		{Username: "ok-user", Password: "short", Role: "operator"},      // weak pw
		{Username: "ok-user", Password: "password1", Role: "wizard"},    // bad role
		{Username: "bad user", Password: "password1", Role: "operator"}, // space
	}
	for _, b := range bad {
		rec := tm.do("POST", "/users", b)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for %+v, got %d", b, rec.Code)
		}
	}
}

func TestCannotDeleteSelf(t *testing.T) {
	tm := newTestModule(t)
	tm.uid = 5
	rec := tm.do("DELETE", "/users/5", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete self should 400, got %d", rec.Code)
	}
}

func TestCannotRemoveLastAdmin(t *testing.T) {
	tm := newTestModule(t)
	// 建一个唯一 admin(id 由 store 决定);用它当目标。
	adminID, _ := tm.m.us.createUser("solo", "h", "admin")
	tm.uid = 999 // 删除者是别人,避免 self-check 抢先
	// 删除最后一个 admin -> 400
	rec := tm.do("DELETE", "/users/"+itoa(adminID), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("deleting last admin should 400, got %d (%s)", rec.Code, rec.Body)
	}
	// 降级最后一个 admin -> 400
	rec = tm.do("PUT", "/users/"+itoa(adminID)+"/role", roleRequest{Role: "operator"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("demoting last admin should 400, got %d", rec.Code)
	}
	// 加第二个 admin 后,降级第一个就允许。
	tm.m.us.createUser("admin2", "h", "admin")
	rec = tm.do("PUT", "/users/"+itoa(adminID)+"/role", roleRequest{Role: "operator"})
	if rec.Code != http.StatusOK {
		t.Fatalf("demote with 2 admins should 200, got %d", rec.Code)
	}
}

func TestResetPassword(t *testing.T) {
	tm := newTestModule(t)
	id, _ := tm.m.us.createUser("target", "oldhash", "operator")
	rec := tm.do("POST", "/users/"+itoa(id)+"/reset-password", passwordRequest{Password: "brandnew1"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d (%s)", rec.Code, rec.Body)
	}
	// 密码哈希必须改变且非明文。
	var h string
	tm.m.us.db.QueryRow("SELECT pass_hash FROM users WHERE id = ?", id).Scan(&h)
	if h == "oldhash" || h == "brandnew1" || h == "" {
		t.Fatalf("password not rehashed: %q", h)
	}
}

// --- 2FA ---

func TestTOTPSetupVerifyDisable(t *testing.T) {
	tm := newTestModule(t)
	uid, _ := tm.m.us.createUser("totper", "h", "operator")
	tm.uid, tm.role = uid, "operator" // 2FA 对任意已认证用户开放

	// setup
	rec := tm.do("POST", "/2fa/setup", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var setup totpSetupResponse
	json.Unmarshal(rec.Body.Bytes(), &setup)
	if setup.Secret == "" || setup.OTPAuthURL == "" {
		t.Fatalf("setup must return secret + url: %+v", setup)
	}

	// 落库的是密文,不是明文。
	var enc string
	tm.m.us.db.QueryRow("SELECT secret_enc FROM user_totp WHERE user_id = ?", tm.uid).Scan(&enc)
	if enc == "" || enc == setup.Secret {
		t.Fatalf("stored secret must be encrypted, got %q (plain %q)", enc, setup.Secret)
	}
	dec, err := tm.m.box.decrypt(enc)
	if err != nil || string(dec) != setup.Secret {
		t.Fatalf("stored ciphertext must decrypt to plaintext secret; err=%v", err)
	}

	// 未启用前 verify 错误码失败。
	rec = tm.do("POST", "/2fa/verify", totpVerifyRequest{Code: "000000"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad code should 401, got %d", rec.Code)
	}
	if row, _ := tm.m.us.getTOTP(tm.uid); row.Enabled {
		t.Fatal("must not enable on wrong code")
	}

	// 正确码 -> 启用。
	code, err := totp.GenerateCode(setup.Secret, timeNow())
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	rec = tm.do("POST", "/2fa/verify", totpVerifyRequest{Code: code})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid code should 200, got %d (%s)", rec.Code, rec.Body)
	}
	if row, _ := tm.m.us.getTOTP(tm.uid); !row.Enabled {
		t.Fatal("should be enabled after valid verify")
	}

	// disable 删除密钥。
	rec = tm.do("POST", "/2fa/disable", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable want 200, got %d", rec.Code)
	}
}

func TestTOTPVerifyWithoutSetup(t *testing.T) {
	tm := newTestModule(t)
	rec := tm.do("POST", "/2fa/verify", totpVerifyRequest{Code: "123456"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("verify without setup should 400, got %d", rec.Code)
	}
}

// --- API Keys ---

func TestAPIKeyEndpoints(t *testing.T) {
	tm := newTestModule(t)
	uid, _ := tm.m.us.createUser("keyer", "h", "readonly")
	tm.uid, tm.role = uid, "readonly" // API Key 对任意已认证用户开放

	rec := tm.do("POST", "/api-keys", apiKeyRequest{Name: "deploy"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d (%s)", rec.Code, rec.Body)
	}
	var created apiKeyCreateResponse
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Key == "" || created.ID == 0 {
		t.Fatalf("must return plaintext key once: %+v", created)
	}

	// 落库只有哈希,无明文。
	var stored string
	tm.m.us.db.QueryRow("SELECT key_hash FROM api_keys WHERE id = ?", created.ID).Scan(&stored)
	if stored == "" || stored == created.Key {
		t.Fatalf("must store hash not plaintext: %q vs %q", stored, created.Key)
	}
	if !apiKeyMatches(created.Key, stored) {
		t.Fatal("returned key must match stored hash")
	}

	// list 不含明文/哈希。
	rec = tm.do("GET", "/api-keys", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list want 200, got %d", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(created.Key)) {
		t.Fatal("list must not leak plaintext key")
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(stored)) {
		t.Fatal("list must not leak key hash")
	}

	// revoke
	rec = tm.do("DELETE", "/api-keys/"+itoa(created.ID), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke want 204, got %d", rec.Code)
	}
	rec = tm.do("DELETE", "/api-keys/"+itoa(created.ID), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("re-revoke want 404, got %d", rec.Code)
	}
}

// --- settings ---

func TestSettingsRoundTrip(t *testing.T) {
	tm := newTestModule(t)
	rec := tm.do("PUT", "/settings", settingsBody{TOTPIssuer: "AcmePanel"})
	if rec.Code != http.StatusOK {
		t.Fatalf("put want 200, got %d (%s)", rec.Code, rec.Body)
	}
	rec = tm.do("GET", "/settings", nil)
	var s settingsBody
	json.Unmarshal(rec.Body.Bytes(), &s)
	if s.TOTPIssuer != "AcmePanel" {
		t.Fatalf("want AcmePanel, got %q", s.TOTPIssuer)
	}
	// 空 issuer 拒绝。
	rec = tm.do("PUT", "/settings", settingsBody{TOTPIssuer: "  "})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty issuer should 400, got %d", rec.Code)
	}
}
