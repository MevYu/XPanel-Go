package config

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// entryPathBody 限定入口路径正文为 1..64 位字母数字(无斜杠),与 entryPathAlphabet 同源。
var entryPathBody = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// ValidateEntryPath 校验隐藏入口路径并返回规范化形式("/" + 正文)。
// 接受可选的单个前导 "/";正文须为 1..64 位字母数字,拒绝空、".."、含斜杠、含空格、过长。
func ValidateEntryPath(p string) (string, error) {
	body := strings.TrimPrefix(p, "/")
	if !entryPathBody.MatchString(body) {
		return "", fmt.Errorf("entry_path: must be 1..64 alphanumeric chars, got %q", p)
	}
	return "/" + body, nil
}

// ValidateAddr 校验监听地址:须为 host:port,port 在 1..65535。host 可空或为 IP/主机名。
func ValidateAddr(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("addr: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("addr: invalid port %q", port)
	}
	if n < 1 || n > 65535 {
		return errors.New("addr: port must be in 1..65535")
	}
	return nil
}

// ValidateTrustedProxies 校验受信反代列表(复用 ParseTrustedProxies 的解析规则)。
func ValidateTrustedProxies(list []string) error {
	_, err := Config{TrustedProxies: list}.ParseTrustedProxies()
	return err
}
