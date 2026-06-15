package appstore

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// 严格白名单:任何未列入的输入直接拒绝,绝不进入 compose 模板或 exec 参数。
// 防 YAML 注入(换行/缩进/引号破坏结构)、命令注入、路径穿越。

// appIDRe 限定应用 id 与实例名:小写字母数字,中间可含 - _,长度受限。
var appIDRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,38}[a-z0-9])?$`)

// instanceNameRe 与 appID 同形,作为 compose 项目名/卷前缀(docker 项目名约束)。
var instanceNameRe = appIDRe

// textRe 限定 text 参数:标识符类,字母数字加 . _ -,无空格/换行/元字符。
var textRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

// passwordRe 限定密码:可见 ASCII 子集,排除 shell/YAML 危险字符(空白、引号、反引号、$、:、#、{}、换行)。
var passwordRe = regexp.MustCompile(`^[A-Za-z0-9!%*+,.\-=@^_~]{8,128}$`)

// validAppID 校验应用 id(白名单)。
func validAppID(id string) bool {
	return appIDRe.MatchString(id)
}

// validInstanceName 校验已安装实例名(白名单),用作 compose 项目名/卷前缀。
func validInstanceName(name string) bool {
	return instanceNameRe.MatchString(name)
}

// validPort 校验端口字符串为 1..65535。
func validPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

// validText 校验受限文本参数。
func validText(s string) bool { return textRe.MatchString(s) }

// validPassword 校验密码参数(长度 + 白名单字符)。
func validPassword(s string) bool { return passwordRe.MatchString(s) }

// validAbsPath 校验绝对路径参数:绝对、无 ..、无元字符、cleaned 形式。
func validAbsPath(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("path must not be empty")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path %q must be absolute", p)
	}
	if strings.ContainsAny(p, "\n\r\t ;{}*?$`\\\"'") {
		return fmt.Errorf("path %q contains forbidden characters", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("path %q must not contain ..", p)
	}
	if filepath.Clean(p) != p {
		return fmt.Errorf("path %q must be in cleaned form", p)
	}
	return nil
}

// validateParams 按应用参数定义校验用户输入,返回填充默认值后的最终参数表。
// 任一字段非法即返回错误,绝不渲染模板。未知键(定义外)被拒绝以防夹带。
func validateParams(app App, in map[string]string) (map[string]string, error) {
	known := make(map[string]bool, len(app.Params))
	out := make(map[string]string, len(app.Params))
	for _, def := range app.Params {
		known[def.Key] = true
		v, ok := in[def.Key]
		v = strings.TrimSpace(v)
		if !ok || v == "" {
			if def.Required && def.Default == "" {
				return nil, fmt.Errorf("param %q is required", def.Key)
			}
			v = def.Default
		}
		if v == "" {
			// 非必填且无默认:跳过(模板需自行容忍缺省)。
			continue
		}
		if err := validateParamValue(def, v); err != nil {
			return nil, fmt.Errorf("param %q: %w", def.Key, err)
		}
		out[def.Key] = v
	}
	for k := range in {
		if !known[k] {
			return nil, fmt.Errorf("unknown param %q", k)
		}
	}
	return out, nil
}

func validateParamValue(def ParamDef, v string) error {
	switch def.Type {
	case ParamPort:
		if !validPort(v) {
			return fmt.Errorf("must be a port 1..65535")
		}
	case ParamPassword:
		if !validPassword(v) {
			return fmt.Errorf("must be 8..128 chars from the allowed set")
		}
	case ParamText:
		if !validText(v) {
			return fmt.Errorf("must be a restricted identifier")
		}
	case ParamPath:
		if err := validAbsPath(v); err != nil {
			return err
		}
	case ParamSelect:
		for _, opt := range def.Options {
			if v == opt {
				return nil
			}
		}
		return fmt.Errorf("must be one of the allowed options")
	default:
		return fmt.Errorf("unsupported param type %q", def.Type)
	}
	return nil
}
