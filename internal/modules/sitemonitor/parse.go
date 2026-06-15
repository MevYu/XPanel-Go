package sitemonitor

import (
	"strconv"
	"strings"
	"time"
)

// Entry 是一条解析后的访问日志记录。未知字段留零值。
type Entry struct {
	IP        string    // 来源 IP($remote_addr)
	Time      time.Time // 请求时间($time_local)
	Method    string    // HTTP 方法
	URL       string    // 请求路径
	Status    int       // 响应状态码
	Bytes     int64     // 响应体字节数($body_bytes_sent)
	Referer   string    // Referer 头
	UserAgent string    // User-Agent 头
	Host      string    // 站点;combined 格式无此字段时为空
}

// timeLayout 是 nginx $time_local 的格式:10/Oct/2000:13:55:36 -0700。
const timeLayout = "02/Jan/2006:15:04:05 -0700"

// ParseCombined 解析一行 nginx combined 格式日志。
//
// combined: $remote_addr - $remote_user [$time_local] "$request" $status
//
//	$body_bytes_sent "$http_referer" "$http_user_agent"
//
// 解析失败(字段缺失/畸形)返回 ok=false,调用方应跳过该行而非中断。
// 逐行调用,刻意省内存:不分配大对象、不 panic。
func ParseCombined(line string) (Entry, bool) {
	var e Entry
	rest := strings.TrimRight(line, "\r\n")
	if rest == "" {
		return e, false
	}

	ip, rest, ok := nextField(rest)
	if !ok {
		return e, false
	}
	e.IP = ip

	// 跳过 "- $remote_user"(两个字段)
	if _, rest, ok = nextField(rest); !ok {
		return e, false
	}
	if _, rest, ok = nextField(rest); !ok {
		return e, false
	}

	tStr, rest, ok := bracketField(rest)
	if !ok {
		return e, false
	}
	if t, err := time.Parse(timeLayout, tStr); err == nil {
		e.Time = t
	}

	req, rest, ok := quotedField(rest)
	if !ok {
		return e, false
	}
	e.Method, e.URL = parseRequest(req)

	statusStr, rest, ok := nextField(rest)
	if !ok {
		return e, false
	}
	status, err := strconv.Atoi(statusStr)
	if err != nil {
		return e, false
	}
	e.Status = status

	// $body_bytes_sent("-" 记为 0)
	bytesStr, rest, ok := nextField(rest)
	if !ok {
		return e, false
	}
	if bytesStr != "-" {
		if n, err := strconv.ParseInt(bytesStr, 10, 64); err == nil {
			e.Bytes = n
		}
	}

	ref, rest, ok := quotedField(rest)
	if !ok {
		return e, false
	}
	e.Referer = ref

	ua, _, ok := quotedField(rest)
	if !ok {
		return e, false
	}
	e.UserAgent = ua

	return e, true
}

// nextField 取下一个以空格分隔的字段,返回字段与剩余串(剩余串已去前导空格)。
func nextField(s string) (field, rest string, ok bool) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return "", "", false
	}
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return s, "", true
	}
	return s[:i], s[i+1:], true
}

// bracketField 取 [...] 包裹的字段(含内部空格,如 time_local)。
func bracketField(s string) (field, rest string, ok bool) {
	s = strings.TrimLeft(s, " ")
	if len(s) == 0 || s[0] != '[' {
		return "", "", false
	}
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return "", "", false
	}
	return s[1:end], s[end+1:], true
}

// quotedField 取 "..." 包裹的字段(支持 \" 转义)。
func quotedField(s string) (field, rest string, ok bool) {
	s = strings.TrimLeft(s, " ")
	if len(s) == 0 || s[0] != '"' {
		return "", "", false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if c == '"' {
			return b.String(), s[i+1:], true
		}
		b.WriteByte(c)
	}
	return "", "", false
}

// parseRequest 把 "GET /path HTTP/1.1" 拆成方法与 URL。畸形请求行尽力而为。
func parseRequest(req string) (method, url string) {
	parts := strings.SplitN(req, " ", 3)
	switch len(parts) {
	case 0:
		return "", ""
	case 1:
		return parts[0], ""
	default:
		return parts[0], parts[1]
	}
}
