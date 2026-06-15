package sites

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// SiteKind 区分三种建站类型。
type SiteKind string

const (
	KindStatic SiteKind = "static" // 纯静态站点,root + index
	KindProxy  SiteKind = "proxy"  // 反向代理到 upstream
	KindPHP    SiteKind = "php"    // PHP-FPM via fastcgi unix socket
)

// VHost 是渲染一个 nginx server 块所需的全部已校验字段。
// 所有字段在 buildVHost 中经白名单校验后才进入此结构;模板不再做任何转义,
// 因为非法字符(换行/分号/空格)在校验阶段已被拒。
type VHost struct {
	Name      string   // 站点名(配置文件名/upstream 名),已校验
	Domains   []string // server_name 列表,已校验
	Listen    int      // 监听端口
	Kind      SiteKind
	Root      string // KindStatic/KindPHP:web 根绝对路径
	Index     string // index 文件,默认 index.html / index.php
	Upstream  string // KindProxy:scheme://host:port,已校验
	PHPSocket string // KindPHP:fastcgi unix socket,已校验
	AccessLog string // 访问日志绝对路径
	ErrorLog  string // 错误日志绝对路径
}

// 模板只插入已校验字段。不依赖模板转义防注入——防线在校验层。
const vhostTmplText = `# Managed by XPanel sites module. Do not edit by hand.
{{- if eq .Kind "proxy"}}
upstream xpanel_{{.Name}} {
    server {{trimscheme .Upstream}};
}
{{- end}}
server {
    listen {{.Listen}};
    server_name{{range .Domains}} {{.}}{{end}};

    access_log {{.AccessLog}};
    error_log {{.ErrorLog}};
{{- if eq .Kind "static"}}

    root {{.Root}};
    index {{.Index}};

    location / {
        try_files $uri $uri/ =404;
    }
{{- else if eq .Kind "php"}}

    root {{.Root}};
    index {{.Index}};

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:{{.PHPSocket}};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
{{- else if eq .Kind "proxy"}}

    location / {
        proxy_pass {{.Upstream}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
{{- end}}
}
`

var vhostTmpl = template.Must(template.New("vhost").Funcs(template.FuncMap{
	// trimscheme 取 upstream 的 host:port 部分供 upstream 块使用。
	"trimscheme": func(u string) string {
		if i := strings.Index(u, "://"); i >= 0 {
			return u[i+3:]
		}
		return u
	},
}).Parse(vhostTmplText))

// renderVHost 渲染配置文本。调用前 VHost 必须已通过 buildVHost 校验。
// 二次防御:渲染后扫描每个已校验输入是否潜入控制字符,若有则拒绝(不应发生)。
func renderVHost(v VHost) (string, error) {
	if err := assertNoInjection(v); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := vhostTmpl.Execute(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// assertNoInjection 是模板渲染前的兜底断言:确保进入模板的字符串字段不含
// 换行/回车(nginx 指令分隔符)。正常流程中校验层已挡住,这里防御调用方绕过校验。
func assertNoInjection(v VHost) error {
	fields := append([]string{v.Name, v.Root, v.Index, v.Upstream, v.PHPSocket, v.AccessLog, v.ErrorLog}, v.Domains...)
	for _, f := range fields {
		if strings.ContainsAny(f, "\n\r") {
			return fmt.Errorf("vhost field contains control character")
		}
	}
	return nil
}
