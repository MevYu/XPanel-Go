package sites

import (
	"fmt"
	"path/filepath"
	"strings"
)

// createRequest 是创建站点的入站载荷(JSON)。所有字段在 buildVHost 中校验。
type createRequest struct {
	Domains   []string `json:"domains"`
	Kind      string   `json:"kind"`     // static | proxy | php
	Listen    int      `json:"listen"`   // 默认 80
	Index     string   `json:"index"`    // 默认按类型
	Upstream  string   `json:"upstream"` // proxy 必填
	PHPSocket string   `json:"php_socket"`
}

// indexRe 限定 index 文件名:空格/分隔的多个简单文件名。
func validIndex(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return false
	}
	for _, f := range strings.Fields(s) {
		if strings.ContainsAny(f, "/\\\n\r;{}") || strings.Contains(f, "..") {
			return false
		}
		if !indexFileRe.MatchString(f) {
			return false
		}
	}
	return true
}

// buildVHost 把入站请求 + 设置校验并组装成可渲染的 VHost。任一字段非法即返回错误,
// 错误信息可安全展示(不含内部路径细节)。site name 由首个域名派生。
func buildVHost(req createRequest, set Settings) (VHost, error) {
	domains := make([]string, len(req.Domains))
	for i, d := range req.Domains {
		domains[i] = strings.ToLower(strings.TrimSpace(d))
	}
	if err := validDomains(domains); err != nil {
		return VHost{}, err
	}

	name := domains[0]
	if strings.HasPrefix(name, "*.") {
		name = strings.TrimPrefix(name, "*.")
	}
	if !validSiteName(name) {
		return VHost{}, fmt.Errorf("cannot derive a valid site name from %q", domains[0])
	}

	listen := req.Listen
	if listen == 0 {
		listen = 80
	}
	if !validListen(listen) {
		return VHost{}, fmt.Errorf("invalid listen port %d", listen)
	}

	v := VHost{
		Name:      name,
		Domains:   domains,
		Listen:    listen,
		AccessLog: filepath.Join(set.LogDir, name+".access.log"),
		ErrorLog:  filepath.Join(set.LogDir, name+".error.log"),
	}

	switch SiteKind(req.Kind) {
	case KindStatic:
		root, err := safeWebRoot(set.WebRoot, name)
		if err != nil {
			return VHost{}, err
		}
		idx := req.Index
		if strings.TrimSpace(idx) == "" {
			idx = "index.html index.htm"
		}
		if !validIndex(idx) {
			return VHost{}, fmt.Errorf("invalid index files")
		}
		v.Kind, v.Root, v.Index = KindStatic, root, strings.TrimSpace(idx)

	case KindPHP:
		root, err := safeWebRoot(set.WebRoot, name)
		if err != nil {
			return VHost{}, err
		}
		if err := validPHPSock(req.PHPSocket); err != nil {
			return VHost{}, err
		}
		idx := req.Index
		if strings.TrimSpace(idx) == "" {
			idx = "index.php index.html"
		}
		if !validIndex(idx) {
			return VHost{}, fmt.Errorf("invalid index files")
		}
		v.Kind, v.Root, v.Index, v.PHPSocket = KindPHP, root, strings.TrimSpace(idx), strings.TrimSpace(req.PHPSocket)

	case KindProxy:
		up, err := validUpstream(req.Upstream)
		if err != nil {
			return VHost{}, err
		}
		v.Kind, v.Upstream = KindProxy, up

	default:
		return VHost{}, fmt.Errorf("invalid kind %q (want static|proxy|php)", req.Kind)
	}

	return v, nil
}
