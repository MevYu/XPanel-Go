package loadbalancer

import (
	"regexp"
	"strings"
)

// 严格白名单:任何未列入的字符直接拒绝,绝不进入 nginx 配置模板。
// 防换行注入(\n/\r 被 nginx 解析为额外指令)、防 shell 元字符、防路径穿越。

// 均衡组名:配置文件名/upstream 块名。字母数字开头,允许 . _ -,无 ..
var groupNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)

// 后端主机:IPv4 或域名(不含通配/scheme/path)。
var backendHostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// 代理监听 server_name:域名或 IP(校验同 backendHost)。
var serverNameRe = backendHostRe

// allowedAlgos 是支持的 nginx 负载均衡算法白名单。值即写入配置的指令(ip_hash/least_conn)
// 或空(round-robin 为默认,不写指令)。
var allowedAlgos = map[string]string{
	"round-robin": "",
	"least_conn":  "least_conn",
	"ip_hash":     "ip_hash",
}

func validAlgo(a string) bool {
	_, ok := allowedAlgos[a]
	return ok
}

func validGroupName(name string) bool {
	return name != "" && len(name) <= 64 && groupNameRe.MatchString(name) && !strings.Contains(name, "..")
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// validBackendHost 校验后端主机:IPv4 或域名,小写,无 scheme/path/端口。
func validBackendHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host != "" && len(host) <= 253 && backendHostRe.MatchString(host)
}

// validServerName 校验代理对外 server_name(域名或 IP)。
func validServerName(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s != "" && len(s) <= 253 && serverNameRe.MatchString(s)
}

// validWeight 校验后端权重 1..100(0 表示未设,调用方填默认 1)。
func validWeight(w int) bool { return w >= 1 && w <= 100 }

// validMaxFails 校验健康检查 max_fails 0..100(0 表示禁用)。
func validMaxFails(n int) bool { return n >= 0 && n <= 100 }

// failTimeoutRe 限定 fail_timeout:正整数 + 可选 s/m 单位(nginx time 语法子集)。
var failTimeoutRe = regexp.MustCompile(`^[1-9][0-9]{0,4}(s|m)?$`)

func validFailTimeout(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && len(s) <= 8 && failTimeoutRe.MatchString(s)
}
