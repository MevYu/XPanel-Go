package waf

import (
	"bufio"
	"os"
	"strings"
)

// Stats 是从 nginx 访问日志聚合出的拦截统计。
// WAF 拦截在生成的配置里表现为 403(规则命中)与 444(连接关闭),
// 限速触发表现为 503/429,这里据响应码归类。
type Stats struct {
	Total     int64 `json:"total"`      // 已扫描的日志行数
	Blocked   int64 `json:"blocked"`    // 403 + 444(规则/IP 拦截)
	Limited   int64 `json:"limited"`    // 503 + 429(CC 限速拒绝)
	LogExists bool  `json:"log_exists"` // 日志文件是否存在(不存在时计数全 0)
}

// maxStatsScan 限制扫描行数,避免超大日志拖垮请求(只取尾部近似统计的上界)。
const maxStatsScan = 200000

// ReadStats 扫描 nginx 访问日志统计拦截。日志不存在返回零值 Stats(非错误):
// 站点刚启用或路径未配置不应让 /stats 报错。解析失败的行被跳过。
//
// 假定默认 combined 日志格式,响应码是第 9 个空白分隔字段:
//
//	IP - - [time] "METHOD uri proto" status bytes ...
func ReadStats(logPath string) (Stats, error) {
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Stats{}, nil
		}
		return Stats{}, err
	}
	defer f.Close()

	var s Stats
	s.LogExists = true
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() && s.Total < maxStatsScan {
		code, ok := statusCode(sc.Text())
		if !ok {
			continue
		}
		s.Total++
		switch code {
		case "403", "444":
			s.Blocked++
		case "503", "429":
			s.Limited++
		}
	}
	if err := sc.Err(); err != nil {
		return s, err
	}
	return s, nil
}

// statusCode 从 combined 日志行取响应码字段(引号请求段之后的首个 token)。
// 返回 ok=false 表示行不可解析。
func statusCode(line string) (string, bool) {
	// 定位请求段的结束引号,响应码紧随其后。
	q := strings.IndexByte(line, '"')
	if q < 0 {
		return "", false
	}
	rest := line[q+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return "", false
	}
	after := strings.TrimSpace(rest[q2+1:])
	fields := strings.Fields(after)
	if len(fields) == 0 {
		return "", false
	}
	code := fields[0]
	if len(code) != 3 || !isDigits(code) {
		return "", false
	}
	return code, true
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
