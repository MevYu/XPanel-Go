package appstore

import (
	"strings"
	"testing"
)

func TestRenderComposeWordPress(t *testing.T) {
	app, _ := LookupApp("wordpress")
	params, err := validateParams(app, map[string]string{"http_port": "8080", "db_password": "S3cret!_pass"})
	if err != nil {
		t.Fatalf("validateParams: %v", err)
	}
	out, err := renderCompose(app, "wordpress-1", params)
	if err != nil {
		t.Fatalf("renderCompose: %v", err)
	}
	if !strings.Contains(out, `"8080:80"`) {
		t.Errorf("port not rendered: %s", out)
	}
	if !strings.Contains(out, `'S3cret!_pass'`) {
		t.Errorf("password not yq-quoted: %s", out)
	}
}

func TestRenderComposeAllAppsParse(t *testing.T) {
	// 每个内置应用用默认参数(必填补最小合法值)应能成功渲染。
	for _, app := range Catalog() {
		in := map[string]string{}
		for _, p := range app.Params {
			switch p.Type {
			case ParamPassword:
				in[p.Key] = "S3cret!_pass"
			default:
				// 其余走默认。
			}
		}
		params, err := validateParams(app, in)
		if err != nil {
			t.Fatalf("%s validateParams: %v", app.ID, err)
		}
		if _, err := renderCompose(app, app.ID+"-1", params); err != nil {
			t.Errorf("%s renderCompose: %v", app.ID, err)
		}
	}
}

// yq 转义即便参数含单引号也不破坏 YAML 结构(防御绕过校验的路径)。
func TestYqQuoteEscapesSingleQuote(t *testing.T) {
	got := yqQuote("a'b")
	if got != "'a''b'" {
		t.Errorf("yqQuote escape wrong: %q", got)
	}
}

// 直接喂未经校验、试图闭合引号注入新键的密码:yq 转义把单引号双写,
// 注入内容仍是同一个单引号标量的一部分,不会变成顶层 YAML 键。
func TestRenderComposeContainsInjectionWithinQuotes(t *testing.T) {
	app, _ := LookupApp("postgres")
	params := map[string]string{"port": "5432", "password": "x', evil: 'y", "db": "app"}
	out, err := renderCompose(app, "pg-1", params)
	if err != nil {
		t.Fatalf("renderCompose: %v", err)
	}
	// 注入的单引号被双写,值整体仍被一对单引号包裹。
	if !strings.Contains(out, `POSTGRES_PASSWORD: 'x'', evil: ''y'`) {
		t.Errorf("injection not safely single-quoted: %s", out)
	}
}
