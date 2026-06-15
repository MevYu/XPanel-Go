package users

import (
	"testing"

	"github.com/pquerna/otp/totp"

	"github.com/MevYu/XPanel-Go/internal/store"
)

const loginTOTPSecret = "host-secret"

// enableTOTP 为用户写入加密 TOTP 密钥并启用,返回明文 base32 密钥。
func enableTOTP(t *testing.T, st *store.Store, userID int64) string {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "X", AccountName: "u"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	us, err := newUserStore(st)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	enc, err := newSecretBox(loginTOTPSecret).encrypt([]byte(key.Secret()))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := us.upsertTOTP(userID, enc, true); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	return key.Secret()
}

// openStore 打开内存库并建一个用户(id=1),满足 user_totp 的外键约束。
func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.CreateUser("u1", "hash", "admin"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return st
}

func TestVerifyLoginTOTP_NotEnabled(t *testing.T) {
	st := openStore(t)
	enabled, ok, err := VerifyLoginTOTP(st, loginTOTPSecret, 1, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if enabled || ok {
		t.Errorf("no totp row: want enabled=false ok=false, got %v %v", enabled, ok)
	}
}

func TestVerifyLoginTOTP_ConfiguredButDisabled(t *testing.T) {
	st := openStore(t)
	us, _ := newUserStore(st)
	enc, _ := newSecretBox(loginTOTPSecret).encrypt([]byte("JBSWY3DPEHPK3PXP"))
	if err := us.upsertTOTP(1, enc, false); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	enabled, ok, err := VerifyLoginTOTP(st, loginTOTPSecret, 1, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if enabled || ok {
		t.Errorf("disabled: want enabled=false ok=false, got %v %v", enabled, ok)
	}
}

func TestVerifyLoginTOTP_EnabledValidCode(t *testing.T) {
	st := openStore(t)
	secret := enableTOTP(t, st, 1)
	code, err := totp.GenerateCode(secret, timeNow())
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	enabled, ok, err := VerifyLoginTOTP(st, loginTOTPSecret, 1, code)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !enabled || !ok {
		t.Errorf("valid code: want enabled=true ok=true, got %v %v", enabled, ok)
	}
}

func TestVerifyLoginTOTP_EnabledWrongCode(t *testing.T) {
	st := openStore(t)
	enableTOTP(t, st, 1)
	enabled, ok, err := VerifyLoginTOTP(st, loginTOTPSecret, 1, "000000")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !enabled {
		t.Errorf("want enabled=true")
	}
	if ok {
		t.Errorf("wrong code should not pass")
	}
}
