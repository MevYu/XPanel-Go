package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Addr             string   `json:"addr"`               // 监听地址,默认 127.0.0.1:8765(不绑 0.0.0.0)
	DBPath           string   `json:"db_path"`            // SQLite 文件路径
	JWTSecret        string   `json:"jwt_secret"`         // base64,首启随机生成
	LoginMaxAttempts int      `json:"login_max_attempts"` // 登录失败达此次数即封禁来源 IP,默认 3
	IPBanHours       int      `json:"ip_ban_hours"`       // IP 封禁时长(小时),默认 72
	EntryPath        string   `json:"entry_path"`         // 隐藏入口路径,首启随机生成(如 /a1b2...)
	TrustedProxies   []string `json:"trusted_proxies"`    // 受信反代 CIDR/IP 列表,默认空;空=只信 RemoteAddr、忽略 XFF

	EntryProbeMax           int `json:"entry_probe_max"`            // 同一 IP 滑动窗口内命中错误路径(入口探测)次数 > 此值即封禁,默认 10
	EntryProbeWindowMinutes int `json:"entry_probe_window_minutes"` // 入口探测计数的滑动窗口分钟数,默认 60

	path string `json:"-"` // 加载来源文件路径,供 Save 回写;不序列化。
}

// ParseTrustedProxies 把 TrustedProxies 解析成网段。裸 IP 视为 /32 或 /128。
// 空列表返回 nil,表示不信任任何代理(忽略 X-Forwarded-For,防伪造)。
func (c Config) ParseTrustedProxies() ([]*net.IPNet, error) {
	if len(c.TrustedProxies) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(c.TrustedProxies))
	for _, entry := range c.TrustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("trusted_proxies: invalid entry %q", entry)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

// Load 读配置文件;不存在则用安全默认值生成并持久化。
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return generate(path)
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}
	if _, err := c.DecodedSecret(); err != nil {
		return Config{}, err
	}
	c.path = path
	// 老配置缺新字段:补默认并回写持久化,使 entry_path 等首次生成后稳定。
	if c.applyDefaults() {
		if err := c.save(path); err != nil {
			return Config{}, err
		}
	}
	return c, nil
}

// applyDefaults 为缺省的安全字段填默认值,返回是否有改动(需回写)。
func (c *Config) applyDefaults() bool {
	changed := false
	if c.LoginMaxAttempts <= 0 {
		c.LoginMaxAttempts = 3
		changed = true
	}
	if c.IPBanHours <= 0 {
		c.IPBanHours = 72
		changed = true
	}
	if c.EntryPath == "" {
		c.EntryPath = randomEntryPath()
		changed = true
	}
	if c.EntryProbeMax <= 0 {
		c.EntryProbeMax = 10
		changed = true
	}
	if c.EntryProbeWindowMinutes <= 0 {
		c.EntryProbeWindowMinutes = 60
		changed = true
	}
	return changed
}

const entryPathAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomEntryPath 生成 "/" + 8 位随机字母数字([a-zA-Z0-9])的隐藏入口路径。
// 拒绝采样消除模偏置(256 不整除 62)。
func randomEntryPath() string {
	const n = 8
	out := make([]byte, n)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			panic(err) // crypto/rand 失败属不可恢复
		}
		if int(buf[0]) >= 256-(256%len(entryPathAlphabet)) {
			continue // 落在不均匀尾段,丢弃重取
		}
		out[i] = entryPathAlphabet[int(buf[0])%len(entryPathAlphabet)]
		i++
	}
	return "/" + string(out)
}

// Save 把当前配置原子回写到加载来源文件(Load 设置的 path)。path 为空则报错。
func (c Config) Save() error {
	if c.path == "" {
		return errors.New("config: no path to save to (not loaded from file)")
	}
	return c.save(c.path)
}

// save 原子写:先写同目录临时文件(0o600)再 rename,避免崩溃留下半截文件。
// 序列化完整 Config(含 jwt_secret),保留未由设置端点管理的字段。
func (c Config) save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// NormalizedEntryPath 返回无尾斜杠的入口路径(根 "/" 除外)。
func (c Config) NormalizedEntryPath() string {
	p := c.EntryPath
	if p != "/" {
		p = strings.TrimRight(p, "/")
	}
	return p
}

// DecodedSecret 解码 JWT 密钥并校验长度,确保签名密钥有效(防被改坏的 config 导致弱/空密钥)。
func (c Config) DecodedSecret() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(c.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("decode jwt_secret: %w", err)
	}
	if len(b) < 32 {
		return nil, errors.New("jwt_secret too short (need >= 32 bytes)")
	}
	return b, nil
}

func generate(path string) (Config, error) {
	secret := make([]byte, 48)
	if _, err := rand.Read(secret); err != nil {
		return Config{}, err
	}
	c := Config{
		Addr:                    "127.0.0.1:8765",
		DBPath:                  "data/xpanel.db",
		JWTSecret:               base64.StdEncoding.EncodeToString(secret),
		LoginMaxAttempts:        3,
		IPBanHours:              72,
		EntryPath:               randomEntryPath(),
		EntryProbeMax:           10,
		EntryProbeWindowMinutes: 60,
		path:                    path,
	}
	if err := c.save(path); err != nil {
		return Config{}, err
	}
	return c, nil
}
