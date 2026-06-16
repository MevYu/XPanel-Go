package loadbalancer

import (
	"fmt"
	"strings"
)

// backendRequest 是入站的单个后端节点载荷。
type backendRequest struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Weight      int    `json:"weight"`       // 0 视为默认 1
	MaxFails    int    `json:"max_fails"`    // 0 视为不写(nginx 默认)
	FailTimeout string `json:"fail_timeout"` // 空视为不写;非空须合法
}

// createRequest 是创建负载均衡组的入站载荷(JSON)。所有字段在 buildGroup 中校验。
type createRequest struct {
	Name       string           `json:"name"`
	Algo       string           `json:"algo"`        // round-robin|least_conn|ip_hash
	Listen     int              `json:"listen"`      // 对外监听端口,默认 80
	ServerName string           `json:"server_name"` // 对外 server_name
	Backends   []backendRequest `json:"backends"`
}

// buildGroup 把入站请求校验并组装成可渲染的 Group。任一字段非法即返回错误,
// 错误信息可安全展示。
func buildGroup(req createRequest) (Group, error) {
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if !validGroupName(name) {
		return Group{}, fmt.Errorf("invalid group name %q", req.Name)
	}

	algo := strings.TrimSpace(req.Algo)
	if algo == "" {
		algo = "round-robin"
	}
	if !validAlgo(algo) {
		return Group{}, fmt.Errorf("invalid algorithm %q (want round-robin|least_conn|ip_hash)", req.Algo)
	}

	listen := req.Listen
	if listen == 0 {
		listen = 80
	}
	if !validPort(listen) {
		return Group{}, fmt.Errorf("invalid listen port %d", listen)
	}

	serverName := strings.ToLower(strings.TrimSpace(req.ServerName))
	if !validServerName(serverName) {
		return Group{}, fmt.Errorf("invalid server_name %q", req.ServerName)
	}

	if len(req.Backends) == 0 {
		return Group{}, fmt.Errorf("at least one backend required")
	}
	if len(req.Backends) > 64 {
		return Group{}, fmt.Errorf("too many backends (max 64)")
	}

	backends := make([]Backend, 0, len(req.Backends))
	seen := make(map[string]bool, len(req.Backends))
	for _, br := range req.Backends {
		host := strings.ToLower(strings.TrimSpace(br.Host))
		if !validBackendHost(host) {
			return Group{}, fmt.Errorf("invalid backend host %q", br.Host)
		}
		if !validPort(br.Port) {
			return Group{}, fmt.Errorf("invalid backend port %d for %q", br.Port, br.Host)
		}
		weight := br.Weight
		if weight == 0 {
			weight = 1
		}
		if !validWeight(weight) {
			return Group{}, fmt.Errorf("invalid backend weight %d (want 1..100)", br.Weight)
		}
		if !validMaxFails(br.MaxFails) {
			return Group{}, fmt.Errorf("invalid max_fails %d (want 0..100)", br.MaxFails)
		}
		ft := strings.TrimSpace(br.FailTimeout)
		if ft != "" && !validFailTimeout(ft) {
			return Group{}, fmt.Errorf("invalid fail_timeout %q", br.FailTimeout)
		}
		addr := fmt.Sprintf("%s:%d", host, br.Port)
		if seen[addr] {
			return Group{}, fmt.Errorf("duplicate backend %q", addr)
		}
		seen[addr] = true
		backends = append(backends, Backend{
			Host: host, Port: br.Port, Weight: weight, MaxFails: br.MaxFails, FailTimeout: ft,
		})
	}

	return Group{
		Name:       name,
		Algo:       algo,
		Listen:     listen,
		ServerName: serverName,
		Backends:   backends,
	}, nil
}
