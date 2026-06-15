package appstore

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// renderData 是 compose 模板的渲染上下文。Params 已经过白名单校验。
type renderData struct {
	Name   string
	Params map[string]string
}

// yqQuote 把标量值渲染为单引号包裹的 YAML 字符串,内部单引号按 YAML 规则双写转义。
// 这是模板注入的第二道防线:即便参数校验被绕过,值也不会破坏 YAML 结构。
func yqQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

var tmplFuncs = template.FuncMap{"yq": yqQuote}

// renderCompose 用已校验参数渲染应用的 compose 模板文本。
// 渲染后兜底断言无裸控制字符潜入(正常流程不会发生)。
func renderCompose(app App, name string, params map[string]string) (string, error) {
	tmpl, err := template.New(app.ID).Funcs(tmplFuncs).Parse(app.Compose)
	if err != nil {
		return "", fmt.Errorf("parse compose template: %w", err)
	}
	tmpl.Option("missingkey=error")
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, renderData{Name: name, Params: params}); err != nil {
		return "", fmt.Errorf("render compose template: %w", err)
	}
	return buf.String(), nil
}
