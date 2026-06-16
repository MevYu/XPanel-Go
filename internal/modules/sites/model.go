package sites

// 本文件定义站点的结构化设置类型(JSON 列),供 store 持久化与模板渲染共用。
// 所有字段进入模板前都必须经 validate.go 校验,模板层不做转义。

// SiteKind 区分三种建站类型。
type SiteKind string

const (
	KindStatic SiteKind = "static" // 纯静态站点,root + index
	KindProxy  SiteKind = "proxy"  // 反向代理到 upstream
	KindPHP    SiteKind = "php"    // PHP-FPM via fastcgi unix socket
)

// Domain 是一个带端口的域名绑定。port 默认 80(SSL 时额外生成 443 块)。
type Domain struct {
	Domain string `json:"domain"`
	Port   int    `json:"port"`
}

// SSL 描述站点的 TLS 配置。证书/私钥以文件路径引用(不入库明文)。
type SSL struct {
	Enabled    bool   `json:"ssl_enabled"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	ForceHTTPS bool   `json:"force_https"` // 开启时 80 块 301 跳 443
	HSTS       bool   `json:"hsts"`        // 开启时 443 块加 Strict-Transport-Security
}

// DirProtect 是一条目录密码保护(auth_basic)。PassHash 为 htpasswd 兼容哈希,绝不明文。
type DirProtect struct {
	Path     string `json:"path"`     // location 前缀,如 /admin
	Username string `json:"username"` // 写入 .htpasswd
	PassHash string `json:"passhash"` // apr1 / bcrypt,非明文
}

// Redirect 是一条 URL 重定向。Code 限 301/302。
type Redirect struct {
	From string `json:"from"` // location 前缀
	To   string `json:"to"`   // 目标 URL 或路径
	Code int    `json:"code"` // 301 | 302
}

// AntiLeech 是防盗链配置:对 Extensions 命中的请求校验 Referer。
type AntiLeech struct {
	Enabled         bool     `json:"enabled"`
	Extensions      []string `json:"extensions"`       // jpg、png、mp4 等(无点)
	AllowedReferers []string `json:"allowed_referers"` // 允许的 referer 主机
}

// ProxyHeader 是一条注入到上游请求的 proxy_set_header。
type ProxyHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ProxyConfig 是反向代理的进阶设置(多上游负载均衡、缓存、自定义头、WebSocket)。
type ProxyConfig struct {
	Upstreams  []string      `json:"upstreams"`   // 每项 scheme://host:port,经 validUpstream,最多 32
	Cache      bool          `json:"cache"`       // 开启 proxy_cache_valid
	CacheTime  int           `json:"cache_time"`  // 秒,1..2592000,Cache 时必填
	SetHeaders []ProxyHeader `json:"set_headers"` // 最多 32
	WebSocket  bool          `json:"websocket"`   // 开启 Upgrade/Connection 头
	SendHost   string        `json:"send_host"`   // "" | "$host" | "$proxy_host" | 合法域名
}

// Limits 是站点级速率/连接限制。零值即不限制。
type Limits struct {
	RateKB int `json:"rate_kb"` // 每连接限速 KB/s,0..1048576,0 不限
	Conn   int `json:"conn"`    // 每客户端 IP 并发连接数,0..65535,0 不限
}

// SiteConfig 是一个站点的全部结构化设置,渲染器据此组合完整 server block。
// 字段对应 sites 表的扩展列。零值即"未设置"。
type SiteConfig struct {
	Name         string       // 站点名(配置文件名/upstream 名)
	Domains      []Domain     // 域名+端口列表
	Kind         SiteKind     // static | php | proxy
	Root         string       // 已校验的 web 根绝对路径(static/php)
	PHPVersion   string       // php 版本如 "8.2",决定 fpm sock
	PHPSocket    string       // 由 PHPVersion 解析出的 fastcgi sock 路径
	IndexDocs    []string     // 默认文档,如 [index.php index.html]
	Upstream     string       // proxy 目标 scheme://host:port
	Proxy        ProxyConfig  // 反代进阶设置(多上游/缓存/头/WebSocket)
	Limits       Limits       // 速率/连接限制
	RewriteRules string       // 伪静态(原始 nginx rewrite 指令,经注入校验)
	SSL          SSL          // TLS
	DirProtect   []DirProtect // 目录保护
	Redirects    []Redirect   // 重定向
	AntiLeech    AntiLeech    // 防盗链
	CustomConfig string       // 追加的原始指令(经注入校验)
	AccessLog    string       // 访问日志绝对路径
	ErrorLog     string       // 错误日志绝对路径
	HtpasswdDir  string       // .htpasswd 写入目录(confDir 同级),渲染 auth_basic_user_file 用
}

// defaultIndexDocs 是新站默认文档。
func defaultIndexDocs() []string { return []string{"index.php", "index.html"} }
