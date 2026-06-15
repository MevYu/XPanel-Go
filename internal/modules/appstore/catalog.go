package appstore

// ParamType 限定参数表单字段的类型,决定渲染与校验规则。
type ParamType string

const (
	ParamPort     ParamType = "port"     // 1..65535
	ParamPassword ParamType = "password" // 8..128,白名单字符,不含 shell/换行
	ParamText     ParamType = "text"     // 受限文本(标识符类),白名单字符
	ParamPath     ParamType = "path"     // 绝对路径,无 .. 无元字符
	ParamSelect   ParamType = "select"   // 必须命中 Options 之一
)

// ParamDef 描述一个应用安装参数的表单定义与校验约束。
type ParamDef struct {
	Key      string    `json:"key"`               // 参数键,模板里以 .Params.<Key> 引用
	Label    string    `json:"label"`             // 前端展示名
	Type     ParamType `json:"type"`              // 字段类型,决定校验
	Default  string    `json:"default"`           // 默认值(port 也用字符串表示)
	Required bool      `json:"required"`          // 是否必填
	Options  []string  `json:"options,omitempty"` // Type=select 时的候选值
}

// App 是内置应用目录中的一个条目:含元信息、参数表单与 compose 模板。
type App struct {
	ID          string     `json:"id"`          // 应用唯一 id,白名单校验
	Name        string     `json:"name"`        // 展示名
	Description string     `json:"description"` // 一句话描述
	Icon        string     `json:"icon"`        // 前端图标 key
	Version     string     `json:"version"`     // 镜像/应用版本标签
	Category    string     `json:"category"`    // 分类(应用/数据库/工具)
	Params      []ParamDef `json:"params"`      // 安装参数表单
	Compose     string     `json:"-"`           // compose 模板文本(text/template),不外泄给前端
}

// catalog 是编译期内置的应用目录,key 为 App.ID。
var catalog map[string]App

// catalogOrder 保持目录稳定输出顺序。
var catalogOrder []string

func init() { catalog = buildCatalog() }

// Catalog 返回全部内置应用(稳定顺序),供 handler 列出。
func Catalog() []App {
	out := make([]App, len(catalogOrder))
	for i, id := range catalogOrder {
		out[i] = catalog[id]
	}
	return out
}

// LookupApp 按 id 取应用定义。
func LookupApp(id string) (App, bool) {
	a, ok := catalog[id]
	return a, ok
}

func buildCatalog() map[string]App {
	apps := []App{
		{
			ID: "wordpress", Name: "WordPress", Description: "流行的开源博客与建站系统",
			Icon: "wordpress", Version: "6", Category: "应用",
			Params: []ParamDef{
				{Key: "http_port", Label: "HTTP 端口", Type: ParamPort, Default: "8080", Required: true},
				{Key: "db_password", Label: "数据库密码", Type: ParamPassword, Default: "", Required: true},
			},
			Compose: wordpressCompose,
		},
		{
			ID: "halo", Name: "Halo", Description: "强大易用的开源建站工具",
			Icon: "halo", Version: "2", Category: "应用",
			Params: []ParamDef{
				{Key: "http_port", Label: "HTTP 端口", Type: ParamPort, Default: "8090", Required: true},
			},
			Compose: haloCompose,
		},
		{
			ID: "gitea", Name: "Gitea", Description: "轻量级自托管 Git 服务",
			Icon: "gitea", Version: "1", Category: "应用",
			Params: []ParamDef{
				{Key: "http_port", Label: "HTTP 端口", Type: ParamPort, Default: "3000", Required: true},
				{Key: "ssh_port", Label: "SSH 端口", Type: ParamPort, Default: "2222", Required: true},
			},
			Compose: giteaCompose,
		},
		{
			ID: "uptime-kuma", Name: "Uptime Kuma", Description: "自托管的监控与状态页工具",
			Icon: "uptime-kuma", Version: "1", Category: "工具",
			Params: []ParamDef{
				{Key: "http_port", Label: "HTTP 端口", Type: ParamPort, Default: "3001", Required: true},
			},
			Compose: uptimeKumaCompose,
		},
		{
			ID: "postgres", Name: "PostgreSQL", Description: "对象关系型数据库",
			Icon: "postgres", Version: "16", Category: "数据库",
			Params: []ParamDef{
				{Key: "port", Label: "端口", Type: ParamPort, Default: "5432", Required: true},
				{Key: "password", Label: "超级用户密码", Type: ParamPassword, Default: "", Required: true},
				{Key: "db", Label: "默认数据库名", Type: ParamText, Default: "app", Required: true},
			},
			Compose: postgresCompose,
		},
		{
			ID: "redis", Name: "Redis", Description: "内存键值存储",
			Icon: "redis", Version: "7", Category: "数据库",
			Params: []ParamDef{
				{Key: "port", Label: "端口", Type: ParamPort, Default: "6379", Required: true},
				{Key: "password", Label: "访问密码", Type: ParamPassword, Default: "", Required: true},
			},
			Compose: redisCompose,
		},
		{
			ID: "mysql", Name: "MySQL", Description: "流行的关系型数据库",
			Icon: "mysql", Version: "8", Category: "数据库",
			Params: []ParamDef{
				{Key: "port", Label: "端口", Type: ParamPort, Default: "3306", Required: true},
				{Key: "root_password", Label: "root 密码", Type: ParamPassword, Default: "", Required: true},
				{Key: "db", Label: "默认数据库名", Type: ParamText, Default: "app", Required: true},
			},
			Compose: mysqlCompose,
		},
		{
			ID: "n8n", Name: "n8n", Description: "工作流自动化平台",
			Icon: "n8n", Version: "1", Category: "工具",
			Params: []ParamDef{
				{Key: "http_port", Label: "HTTP 端口", Type: ParamPort, Default: "5678", Required: true},
			},
			Compose: n8nCompose,
		},
	}
	m := make(map[string]App, len(apps))
	catalogOrder = make([]string, 0, len(apps))
	for _, a := range apps {
		m[a.ID] = a
		catalogOrder = append(catalogOrder, a.ID)
	}
	return m
}
