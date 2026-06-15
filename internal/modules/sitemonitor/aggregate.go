package sitemonitor

import (
	"sort"
	"time"
)

// TimeRange 限定分析的时间窗。零值字段表示该端不限。
type TimeRange struct {
	From time.Time
	To   time.Time
}

// contains 报告 t 是否落在范围内(From/To 为零值时对应端不限)。
func (r TimeRange) contains(t time.Time) bool {
	if !r.From.IsZero() && t.Before(r.From) {
		return false
	}
	if !r.To.IsZero() && t.After(r.To) {
		return false
	}
	return true
}

// StatusBuckets 是状态码按类分布。
type StatusBuckets struct {
	XX2 int64 `json:"2xx"`
	XX3 int64 `json:"3xx"`
	XX4 int64 `json:"4xx"`
	XX5 int64 `json:"5xx"`
	Oth int64 `json:"other"`
}

// Count 是一个 (键, 计数) 对,用于 Top 列表。
type Count struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// SiteStat 是单站点(host)的聚合。
type SiteStat struct {
	Host     string `json:"host"`
	Requests int64  `json:"requests"`
	Bytes    int64  `json:"bytes"`
}

// TrendPoint 是一个时间桶的请求/带宽。
type TrendPoint struct {
	Bucket   string `json:"bucket"` // RFC3339 截断到桶粒度
	Requests int64  `json:"requests"`
	Bytes    int64  `json:"bytes"`
}

// Report 是一次分析的完整聚合结果。
type Report struct {
	TotalRequests int64         `json:"total_requests"`
	TotalBytes    int64         `json:"total_bytes"`
	UniqueIPs     int64         `json:"unique_ips"` // UV
	Status        StatusBuckets `json:"status"`
	Sites         []SiteStat    `json:"sites"`
	TopURLs       []Count       `json:"top_urls"`
	TopIPs        []Count       `json:"top_ips"`
	TopUAs        []Count       `json:"top_uas"`
}

// Aggregator 增量累计各类统计,可逐行喂入,避免把全部 Entry 留在内存。
type Aggregator struct {
	rng TimeRange

	total  int64
	bytes  int64
	status StatusBuckets
	ips    map[string]int64
	urls   map[string]int64
	uas    map[string]int64
	sites  map[string]*SiteStat
}

// NewAggregator 建一个限定在 rng 内的聚合器(rng 零值表示不限时间)。
func NewAggregator(rng TimeRange) *Aggregator {
	return &Aggregator{
		rng:   rng,
		ips:   map[string]int64{},
		urls:  map[string]int64{},
		uas:   map[string]int64{},
		sites: map[string]*SiteStat{},
	}
}

// Add 累计一条记录;时间在窗外则跳过(Time 为零值的记录视为不限时间,始终计入)。
func (a *Aggregator) Add(e Entry) {
	if !e.Time.IsZero() && !a.rng.contains(e.Time) {
		return
	}
	a.total++
	a.bytes += e.Bytes
	a.bucketStatus(e.Status)
	if e.IP != "" {
		a.ips[e.IP]++
	}
	if e.URL != "" {
		a.urls[e.URL]++
	}
	if e.UserAgent != "" {
		a.uas[e.UserAgent]++
	}
	host := e.Host
	if host == "" {
		host = "-"
	}
	s := a.sites[host]
	if s == nil {
		s = &SiteStat{Host: host}
		a.sites[host] = s
	}
	s.Requests++
	s.Bytes += e.Bytes
}

func (a *Aggregator) bucketStatus(code int) {
	switch {
	case code >= 200 && code < 300:
		a.status.XX2++
	case code >= 300 && code < 400:
		a.status.XX3++
	case code >= 400 && code < 500:
		a.status.XX4++
	case code >= 500 && code < 600:
		a.status.XX5++
	default:
		a.status.Oth++
	}
}

// Report 产出聚合结果;topN 限定各 Top 列表长度(<=0 用 10)。
func (a *Aggregator) Report(topN int) Report {
	if topN <= 0 {
		topN = 10
	}
	sites := make([]SiteStat, 0, len(a.sites))
	for _, s := range a.sites {
		sites = append(sites, *s)
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].Requests != sites[j].Requests {
			return sites[i].Requests > sites[j].Requests
		}
		return sites[i].Host < sites[j].Host
	})
	return Report{
		TotalRequests: a.total,
		TotalBytes:    a.bytes,
		UniqueIPs:     int64(len(a.ips)),
		Status:        a.status,
		Sites:         sites,
		TopURLs:       topCounts(a.urls, topN),
		TopIPs:        topCounts(a.ips, topN),
		TopUAs:        topCounts(a.uas, topN),
	}
}

// Sites 列出单站点聚合(按请求数降序)。
func (a *Aggregator) Sites() []SiteStat {
	r := a.Report(1)
	return r.Sites
}

// Trend 按 bucket 粒度("hour"/"day")汇总时间趋势,按时间升序。
// 需重放 Entry(趋势不能从最终聚合反推),故单独提供。
func Trend(entries []Entry, rng TimeRange, granularity string) []TrendPoint {
	buckets := map[time.Time]*TrendPoint{}
	for _, e := range entries {
		if e.Time.IsZero() || !rng.contains(e.Time) {
			continue
		}
		key := truncateTo(e.Time, granularity)
		p := buckets[key]
		if p == nil {
			p = &TrendPoint{Bucket: key.Format(time.RFC3339)}
			buckets[key] = p
		}
		p.Requests++
		p.Bytes += e.Bytes
	}
	keys := make([]time.Time, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
	out := make([]TrendPoint, 0, len(keys))
	for _, k := range keys {
		out = append(out, *buckets[k])
	}
	return out
}

// truncateTo 把时间截断到桶粒度;未知粒度默认按小时。
func truncateTo(t time.Time, granularity string) time.Time {
	if granularity == "day" {
		y, m, d := t.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
	}
	return t.Truncate(time.Hour)
}

// topCounts 取 map 中计数最高的 n 个,按计数降序、键升序稳定排序。
func topCounts(m map[string]int64, n int) []Count {
	all := make([]Count, 0, len(m))
	for k, v := range m {
		all = append(all, Count{Key: k, Count: v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Count != all[j].Count {
			return all[i].Count > all[j].Count
		}
		return all[i].Key < all[j].Key
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}
