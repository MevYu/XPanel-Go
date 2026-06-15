package users

import (
	"errors"

	"github.com/pquerna/otp/totp"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// VerifyLoginTOTP 供宿主在登录时强制 2FA。读取该用户的 TOTP 状态:
//   - 未配置或未启用 → enabled=false, ok=false, err=nil(调用方据此放行,不要求 code)。
//   - 已启用 → enabled=true, ok 为 code 是否通过 totp 校验。
//
// secret 必须与构造 Module 时传入的相同(= cfg.JWTSecret),用于派生解密密钥。
// 防重放依赖 pquerna/otp 默认时间窗口。解密失败按 err 返回,调用方应拒绝登录而非放行。
func VerifyLoginTOTP(st *store.Store, secret string, userID int64, code string) (enabled, ok bool, err error) {
	us, err := newUserStore(st)
	if err != nil {
		return false, false, err
	}
	row, err := us.getTOTP(userID)
	if errors.Is(err, errNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if !row.Enabled {
		return false, false, nil
	}
	plain, err := newSecretBox(secret).decrypt(row.SecretEnc)
	if err != nil {
		return true, false, err
	}
	return true, totp.Validate(code, string(plain)), nil
}
