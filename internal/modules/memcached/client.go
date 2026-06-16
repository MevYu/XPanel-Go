package memcached

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Client 抽象与 memcached 的交互,便于在无 memcached 的环境用 mock 测试。
type Client interface {
	// Stats 发 "stats" 命令,返回原始 key→value 映射。
	Stats(addr string) (map[string]string, error)
	// Slabs 发 "stats slabs" 命令,返回每个 slab class 的 key→value 映射(class id → 字段)。
	Slabs(addr string) (map[string]map[string]string, error)
	// FlushAll 发 "flush_all" 命令清空所有缓存(危险)。
	FlushAll(addr string) error
}

// dialTimeout 是连接/读写的统一超时,挡住 memcached 卡死拖垮请求。
const dialTimeout = 3 * time.Second

// netClient 是基于 stdlib net 的文本协议实现。
type netClient struct{}

// NewClient 返回默认的 net 实现。
func NewClient() Client { return netClient{} }

// dial 建连并设整体 deadline。
func dial(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	return conn, nil
}

func (netClient) Stats(addr string) (map[string]string, error) {
	conn, err := dial(addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "stats\r\n"); err != nil {
		return nil, err
	}
	return parseStats(bufio.NewReader(conn))
}

func (netClient) Slabs(addr string) (map[string]map[string]string, error) {
	conn, err := dial(addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "stats slabs\r\n"); err != nil {
		return nil, err
	}
	flat, err := parseStats(bufio.NewReader(conn))
	if err != nil {
		return nil, err
	}
	return groupSlabs(flat), nil
}

func (netClient) FlushAll(addr string) error {
	conn, err := dial(addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "flush_all\r\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "OK" {
		return fmt.Errorf("memcached: flush_all returned %q", strings.TrimSpace(line))
	}
	return nil
}

// parseStats 解析 memcached "STAT <key> <value>" 行,直到 "END"。
// 返回最后一个同名 key(memcached stats 无重名,保留行为简单)。
func parseStats(r *bufio.Reader) (map[string]string, error) {
	out := make(map[string]string)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF && len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "END" {
			return out, nil
		}
		if line == "ERROR" || strings.HasPrefix(line, "CLIENT_ERROR") || strings.HasPrefix(line, "SERVER_ERROR") {
			return nil, fmt.Errorf("memcached: %s", line)
		}
		// 期望: STAT <key> <value>
		fields := strings.SplitN(line, " ", 3)
		if len(fields) != 3 || fields[0] != "STAT" {
			continue // 容忍未知行
		}
		out[fields[1]] = fields[2]
	}
}

// groupSlabs 把 "stats slabs" 的扁平 key 按 slab class 分组。
// memcached 形如 "<classid>:<field>"(如 "1:chunk_size"),非此形的(如 active_slabs/total_malloced)归到 "_global"。
func groupSlabs(flat map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string)
	for k, v := range flat {
		cls, field, ok := strings.Cut(k, ":")
		if !ok {
			cls, field = "_global", k
		}
		if out[cls] == nil {
			out[cls] = make(map[string]string)
		}
		out[cls][field] = v
	}
	return out
}

// Stats 是给前端的归一化统计快照,从原始 stats map 计算出命中率等派生指标。
type Stats struct {
	PID              int64             `json:"pid"`
	Uptime           int64             `json:"uptime"`
	Version          string            `json:"version"`
	CurrConnections  int64             `json:"curr_connections"`
	TotalConnections int64             `json:"total_connections"`
	CurrItems        int64             `json:"curr_items"`
	TotalItems       int64             `json:"total_items"`
	BytesUsed        int64             `json:"bytes"`
	LimitMaxBytes    int64             `json:"limit_maxbytes"`
	GetHits          int64             `json:"get_hits"`
	GetMisses        int64             `json:"get_misses"`
	CmdGet           int64             `json:"cmd_get"`
	CmdSet           int64             `json:"cmd_set"`
	Evictions        int64             `json:"evictions"`
	HitRate          float64           `json:"hit_rate"`       // get_hits/(get_hits+get_misses),0..1
	MemUsageRate     float64           `json:"mem_usage_rate"` // bytes/limit_maxbytes,0..1
	Raw              map[string]string `json:"raw"`
}

// buildStats 把原始 stats map 归一化为 Stats,缺字段按 0/空处理。
func buildStats(raw map[string]string) Stats {
	atoi := func(k string) int64 {
		n, _ := strconv.ParseInt(raw[k], 10, 64)
		return n
	}
	s := Stats{
		PID:              atoi("pid"),
		Uptime:           atoi("uptime"),
		Version:          raw["version"],
		CurrConnections:  atoi("curr_connections"),
		TotalConnections: atoi("total_connections"),
		CurrItems:        atoi("curr_items"),
		TotalItems:       atoi("total_items"),
		BytesUsed:        atoi("bytes"),
		LimitMaxBytes:    atoi("limit_maxbytes"),
		GetHits:          atoi("get_hits"),
		GetMisses:        atoi("get_misses"),
		CmdGet:           atoi("cmd_get"),
		CmdSet:           atoi("cmd_set"),
		Evictions:        atoi("evictions"),
		Raw:              raw,
	}
	if gets := s.GetHits + s.GetMisses; gets > 0 {
		s.HitRate = float64(s.GetHits) / float64(gets)
	}
	if s.LimitMaxBytes > 0 {
		s.MemUsageRate = float64(s.BytesUsed) / float64(s.LimitMaxBytes)
	}
	return s
}
