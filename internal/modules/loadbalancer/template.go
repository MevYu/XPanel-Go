package loadbalancer

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// Backend 是一个已校验的后端节点。Addr 为 host:port,Weight 1..100。
type Backend struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Weight      int    `json:"weight"`
	MaxFails    int    `json:"max_fails"`    // 健康检查:连续失败多少次标记不可用(0=nginx 默认)
	FailTimeout string `json:"fail_timeout"` // 不可用持续时间,如 "30s"
}

// Addr 返回 host:port 文本(已校验,可直接进模板)。
func (b Backend) Addr() string { return fmt.Sprintf("%s:%d", b.Host, b.Port) }

// Group 是一个负载均衡组(对应一个 nginx upstream + 配套 server 块)。
// 所有字段经 buildGroup 白名单校验后才进入此结构;模板不再转义。
type Group struct {
	Name       string    // upstream/配置文件名,已校验
	Algo       string    // round-robin|least_conn|ip_hash,已校验
	Listen     int       // 对外代理监听端口
	ServerName string    // 对外 server_name(域名或 IP),已校验
	Backends   []Backend // 至少一个,已校验
}

// algoDirective 返回算法对应的 nginx 指令行(round-robin 为默认,空)。
func (g Group) algoDirective() string { return allowedAlgos[g.Algo] }

// 模板只插入已校验字段。不依赖模板转义防注入——防线在校验层。
const lbTmplText = `# Managed by XPanel loadbalancer module. Do not edit by hand.
upstream xpanel_lb_{{.Name}} {
{{- with .AlgoDir}}
    {{.}};
{{- end}}
{{- range .Backends}}
    server {{.Addr}} weight={{.Weight}}{{if .MaxFails}} max_fails={{.MaxFails}}{{end}}{{if .FailTimeout}} fail_timeout={{.FailTimeout}}{{end}};
{{- end}}
}
server {
    listen {{.Listen}};
    server_name {{.ServerName}};

    location / {
        proxy_pass http://xpanel_lb_{{.Name}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`

var lbTmpl = template.Must(template.New("lb").Parse(lbTmplText))

// renderGroup 渲染配置文本。调用前 Group 必须已通过 buildGroup 校验。
// 二次防御:渲染前断言无控制字符潜入(正常流程不应触发)。
func renderGroup(g Group) (string, error) {
	if err := assertNoInjection(g); err != nil {
		return "", err
	}
	data := struct {
		Group
		AlgoDir string
	}{Group: g, AlgoDir: g.algoDirective()}
	var buf bytes.Buffer
	if err := lbTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// assertNoInjection 是模板渲染前的兜底断言:确保进入模板的字符串字段不含换行/回车
// (nginx 指令分隔符)。正常流程中校验层已挡住,这里防御调用方绕过校验。
func assertNoInjection(g Group) error {
	fields := []string{g.Name, g.Algo, g.ServerName}
	for _, b := range g.Backends {
		fields = append(fields, b.Host, b.FailTimeout)
	}
	for _, f := range fields {
		if strings.ContainsAny(f, "\n\r") {
			return fmt.Errorf("group field contains control character")
		}
	}
	return nil
}
