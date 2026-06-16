package sites

import (
	"fmt"
	"path/filepath"
	"strings"
)

// createRequest 是创建站点的入站载荷(JSON)。所有字段在 buildSite 中校验。
type createRequest struct {
	Name       string   `json:"name"`     // 可选:站点名;空则由首个域名派生
	Domains    []string `json:"domains"`  // 纯域名;或用 DomainBindings 带端口
	Bindings   []Domain `json:"bindings"` // 可选:带端口的域名绑定
	Kind       string   `json:"kind"`     // static | php | proxy
	Listen     int      `json:"listen"`   // 默认 80
	Root       string   `json:"root"`     // 可选:覆盖默认 web 根(相对站点名)
	Index      string   `json:"index"`    // 默认按类型
	IndexDocs  []string `json:"index_docs"`
	Upstream   string   `json:"upstream"`     // proxy 必填(亦接受 proxy_target)
	Proxy      string   `json:"proxy_target"` // 同 Upstream 别名
	PHPVersion string   `json:"php_version"`
	PHPSocket  string   `json:"php_socket"`
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

// buildSite 把创建请求 + 设置校验组装成一条新 Site(含解析后的 root/socket/日志路径)。
// 任一字段非法即返回错误。Config 字段留空,由调用方渲染后填入。
func buildSite(req createRequest, set Settings) (Site, error) {
	bindings, err := buildBindings(req)
	if err != nil {
		return Site{}, err
	}

	name := strings.ToLower(strings.TrimSpace(req.Name))
	if name == "" {
		name = strings.TrimPrefix(bindings[0].Domain, "*.")
	}
	if !validSiteName(name) {
		return Site{}, fmt.Errorf("invalid site name %q", name)
	}

	listen := req.Listen
	if listen == 0 {
		listen = 80
	}
	if !validListen(listen) {
		return Site{}, fmt.Errorf("invalid listen port %d", listen)
	}

	st := Site{
		Name:           name,
		Domains:        domainsOf(bindings),
		DomainBindings: bindings,
		Listen:         listen,
		Enabled:        true,
		LogEnabled:     true,
		AccessLog:      filepath.Join(set.LogDir, name+".access.log"),
		ErrorLog:       filepath.Join(set.LogDir, name+".error.log"),
		IndexDocs:      defaultIndexDocs(),
	}
	if len(req.IndexDocs) > 0 {
		if err := validIndexDocs(req.IndexDocs); err != nil {
			return Site{}, err
		}
		st.IndexDocs = req.IndexDocs
	}

	switch SiteKind(req.Kind) {
	case KindStatic:
		root, err := safeWebRoot(set.WebRoot, name)
		if err != nil {
			return Site{}, err
		}
		st.Kind, st.RootDir = string(KindStatic), root
		if len(req.IndexDocs) == 0 {
			st.IndexDocs = []string{"index.html", "index.htm"}
		}

	case KindPHP:
		root, err := safeWebRoot(set.WebRoot, name)
		if err != nil {
			return Site{}, err
		}
		if req.PHPVersion != "" && !validPHPVersion(req.PHPVersion) {
			return Site{}, fmt.Errorf("invalid php version %q", req.PHPVersion)
		}
		// php socket 由版本解析;显式 socket 仅在版本空时作为兜底校验。
		if req.PHPVersion == "" {
			if err := validPHPSock(orDefault(req.PHPSocket, set.PHPSocket)); err != nil {
				return Site{}, err
			}
		}
		st.Kind, st.RootDir, st.PHPVersion = string(KindPHP), root, req.PHPVersion

	case KindProxy:
		up, err := validUpstream(orDefault(req.Upstream, req.Proxy))
		if err != nil {
			return Site{}, err
		}
		st.Kind, st.ProxyTarget = string(KindProxy), up

	default:
		return Site{}, fmt.Errorf("invalid kind %q (want static|proxy|php)", req.Kind)
	}

	return st, nil
}

// buildBindings 归一并校验域名绑定:接受 Bindings(带端口)或 Domains(纯域名,端口取 listen/80)。
func buildBindings(req createRequest) ([]Domain, error) {
	var bs []Domain
	if len(req.Bindings) > 0 {
		for _, b := range req.Bindings {
			d := Domain{Domain: strings.ToLower(strings.TrimSpace(b.Domain)), Port: b.Port}
			if err := validDomainBinding(d); err != nil {
				return nil, err
			}
			if d.Port == 0 {
				d.Port = 80
			}
			bs = append(bs, d)
		}
	} else {
		port := req.Listen
		if port == 0 {
			port = 80
		}
		for _, raw := range req.Domains {
			d := Domain{Domain: strings.ToLower(strings.TrimSpace(raw)), Port: port}
			if err := validDomainBinding(d); err != nil {
				return nil, err
			}
			bs = append(bs, d)
		}
	}
	if len(bs) == 0 {
		return nil, fmt.Errorf("at least one domain required")
	}
	if len(bs) > 32 {
		return nil, fmt.Errorf("too many domains (max 32)")
	}
	seen := map[string]bool{}
	for _, b := range bs {
		if seen[b.Domain] {
			return nil, fmt.Errorf("duplicate domain %q", b.Domain)
		}
		seen[b.Domain] = true
	}
	return bs, nil
}

// validIndexDocs 校验默认文档列表。
func validIndexDocs(docs []string) error {
	if len(docs) == 0 || len(docs) > 16 {
		return fmt.Errorf("index docs count out of range")
	}
	for _, d := range docs {
		if !indexFileRe.MatchString(d) || strings.Contains(d, "..") {
			return fmt.Errorf("invalid index doc %q", d)
		}
	}
	return nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
