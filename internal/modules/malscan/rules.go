package malscan

import "regexp"

// Severity 是规则命中的危险等级。分数累加后决定文件是否可疑。
type Severity int

const (
	SevLow      Severity = 1  // 单独出现不足以定性,需配合其它命中
	SevMedium   Severity = 5  // 强可疑特征
	SevHigh     Severity = 10 // 典型 webshell 特征,单条即足以标记
	SevCritical Severity = 20 // 一句话木马等几乎可确定为后门
)

// Rule 是一条静态特征规则。re 在文件文本上逐行匹配,命中即按 Score 计分。
type Rule struct {
	ID    string   // 稳定标识,用于命中记录与白名单
	Name  string   // 人类可读名称
	Score Severity // 命中得分
	re    *regexp.Regexp
}

// Pattern 返回规则正则的源串(供前端/审计展示,不暴露内部 *regexp)。
func (r Rule) Pattern() string { return r.re.String() }

// builtinRules 是内置 webshell/木马静态特征集。可扩展:新增一条 mustRule 即可。
// 设计取向:宁可多条低分特征组合判定,也不用单条宽泛正则,降低对正常代码的误报。
var builtinRules = []Rule{
	// 一句话木马:把请求参数直接喂给代码执行函数,几乎可确定为后门。
	mustRule("oneliner_eval_request", "一句话木马 (eval/assert + 请求变量)", SevCritical,
		`(?i)\b(?:eval|assert)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)`),
	mustRule("oneliner_preg_e", "preg_replace /e 修饰符代码执行", SevCritical,
		`(?i)preg_replace\s*\(\s*['"].*/e['"]`),
	mustRule("create_function_request", "create_function 注入请求变量", SevCritical,
		`(?i)create_function\s*\(.*\$_(?:POST|GET|REQUEST|COOKIE)`),

	// 动态执行 + 请求变量(变量函数调用、回调执行)。
	mustRule("callback_exec_request", "回调执行请求变量 (call_user_func/array_map 等)", SevHigh,
		`(?i)(?:call_user_func(?:_array)?|array_map|array_filter)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)`),
	mustRule("system_exec_request", "命令执行函数 + 请求变量", SevHigh,
		`(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)`),

	// base64/gzinflate 解码后立即执行:典型混淆 webshell 加载器。
	mustRule("eval_base64_decode", "eval(base64_decode(...)) 混淆载荷", SevHigh,
		`(?i)\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(`),
	mustRule("eval_gzinflate_chain", "eval(gzinflate(base64_decode(...))) 多层混淆", SevHigh,
		`(?i)eval\s*\(\s*gzinflate\s*\(\s*(?:base64_decode|str_rot13)`),

	// 变量函数调用形式的隐蔽执行:$func($_POST[...])。
	mustRule("dynamic_var_func", "变量函数调用 (可能为隐蔽后门)", SevMedium,
		`(?i)\$[a-z_][a-z0-9_]*\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)`),

	// 危险函数本身(低分,需配合其它命中才会触发阈值)。
	mustRule("danger_func_eval", "危险函数 eval/assert", SevLow,
		`(?i)\b(?:eval|assert)\s*\(`),
	mustRule("danger_func_system", "危险函数 system/exec/passthru/shell_exec", SevLow,
		`(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(`),
	mustRule("danger_func_base64", "base64_decode 解码", SevLow,
		`(?i)\bbase64_decode\s*\(`),

	// 混淆特征:大段十六进制/八进制转义、超长 base64 串。
	mustRule("obfuscation_chr_chain", "chr() 拼接混淆字符串", SevMedium,
		`(?i)(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){4,}`),
	mustRule("obfuscation_long_base64", "超长 base64 字面量 (疑似内嵌载荷)", SevMedium,
		`['"][A-Za-z0-9+/]{200,}={0,2}['"]`),
	mustRule("obfuscation_hex_escapes", "密集十六进制转义混淆", SevMedium,
		`(?:\\x[0-9a-fA-F]{2}){8,}`),

	// 文件上传后门特征。
	mustRule("move_uploaded_file", "move_uploaded_file (上传落地后门)", SevLow,
		`(?i)move_uploaded_file\s*\(`),

	// ASP/JSP webshell 特征。
	mustRule("asp_eval_request", "ASP Eval/Execute 请求变量", SevCritical,
		`(?i)(?:eval|execute)\s*\(\s*request`),
	mustRule("jsp_runtime_exec", "JSP Runtime.exec (命令执行)", SevHigh,
		`(?i)Runtime\.getRuntime\(\)\.exec\s*\(`),
}

// mustRule 编译规则正则,失败 panic:内置规则是代码常量,编译失败属编程错误。
func mustRule(id, name string, score Severity, pattern string) Rule {
	return Rule{ID: id, Name: name, Score: score, re: regexp.MustCompile(pattern)}
}
