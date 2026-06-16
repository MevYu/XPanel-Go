package memcached

import (
	"fmt"
	"net"
	"strings"
)

// Settings 是 memcached 模块的可配置项,可由 admin 经 PUT /settings 修改。
type Settings struct {
	// Addr 是 memcached 的连接地址(host:port),文本协议命令都发往此处。
	Addr string `json:"addr"`
	// ServiceUnit 是 systemd 单元名,用于启停/重启服务。
	ServiceUnit string `json:"service_unit"`
}

// DefaultSettings 返回出厂默认(对标 aaPanel 的本机 memcached 默认监听与单元名)。
func DefaultSettings() Settings {
	return Settings{
		Addr:        "127.0.0.1:11211",
		ServiceUnit: "memcached",
	}
}

// unitNameOK 复刻 system 包的单元名白名单,避免反向依赖:字母数字 . _ - @,长度受限。
func unitNameOK(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-' || c == '@':
		default:
			return false
		}
	}
	return true
}

// Validate 严格校验设置:地址须为合法 host:port,单元名须过白名单。
func (s Settings) Validate() error {
	if strings.ContainsAny(s.Addr, "\n\r\x00") {
		return fmt.Errorf("memcached: addr must not contain control chars")
	}
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return fmt.Errorf("memcached: addr must be host:port: %w", err)
	}
	if host == "" {
		return fmt.Errorf("memcached: addr host must not be empty")
	}
	if port == "" {
		return fmt.Errorf("memcached: addr port must not be empty")
	}
	if !unitNameOK(s.ServiceUnit) {
		return fmt.Errorf("memcached: service_unit must match [a-zA-Z0-9._@-]{1,128}")
	}
	return nil
}
