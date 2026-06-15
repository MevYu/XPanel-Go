package alert

import (
	"fmt"
	"time"

	"github.com/MevYu/XPanel-Go/internal/system"
)

// Metric 是可监控的指标种类。
type Metric string

const (
	MetricCPU    Metric = "cpu"     // CPU 使用率 %
	MetricMemory Metric = "memory"  // 内存使用率 %
	MetricDisk   Metric = "disk"    // 根分区磁盘使用率 %
	MetricLoad   Metric = "load"    // 1 分钟系统负载
	MetricDiskIO Metric = "disk_io" // 所有设备读写字节速率之和(bytes/s,需相邻两次采样差分)
)

// validMetric 报告 m 是否为已知指标。
func validMetric(m Metric) bool {
	switch m {
	case MetricCPU, MetricMemory, MetricDisk, MetricLoad, MetricDiskIO:
		return true
	}
	return false
}

// Comparator 是阈值比较符。
type Comparator string

const (
	GreaterThan Comparator = "gt"
	LessThan    Comparator = "lt"
)

// validComparator 报告 c 是否为已知比较符。
func validComparator(c Comparator) bool {
	return c == GreaterThan || c == LessThan
}

// compare 报告 value 与 threshold 在 cmp 下是否成立。
func (c Comparator) compare(value, threshold float64) bool {
	switch c {
	case GreaterThan:
		return value > threshold
	case LessThan:
		return value < threshold
	}
	return false
}

// sample 是一次完整指标采样,所有比率为 0-100 的百分数。
// DiskIOBytes 为采样瞬间所有设备累计读写字节之和(用于跨样本差分求速率)。
type sample struct {
	cpu         float64
	memory      float64
	disk        float64
	load1       float64
	diskIOBytes uint64
	at          time.Time
}

// value 返回采样中某指标的数值。DiskIO 在此返回累计字节,速率差分由 evaluator 处理。
func (s sample) value(m Metric) float64 {
	switch m {
	case MetricCPU:
		return s.cpu
	case MetricMemory:
		return s.memory
	case MetricDisk:
		return s.disk
	case MetricLoad:
		return s.load1
	case MetricDiskIO:
		return float64(s.diskIOBytes)
	}
	return 0
}

// collectSample 采集一次系统指标(只读调用 system 包)。
func collectSample() (sample, error) {
	m, err := system.Snapshot()
	if err != nil {
		return sample{}, err
	}
	d, err := system.DetailSnapshot()
	if err != nil {
		return sample{}, err
	}
	var ioTotal uint64
	for _, io := range d.DiskIO {
		ioTotal += io.ReadBytes + io.WriteBytes
	}
	return sample{
		cpu:         m.CPUPercent,
		memory:      pct(m.MemUsed, m.MemTotal),
		disk:        pct(m.DiskUsed, m.DiskTotal),
		load1:       d.Load.Load1,
		diskIOBytes: ioTotal,
		at:          time.Now(),
	}, nil
}

// pct 计算 used/total 百分比,total 为 0 时返回 0。
func pct(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

// metricValue 从当前采样(及上一采样用于 disk_io 差分)解出规则关心的指标实测值。
// 对 disk_io 返回 bytes/s 速率;prev 为零值(无上一样本)时 disk_io 返回 0(无法差分)。
func metricValue(m Metric, cur, prev sample) float64 {
	if m != MetricDiskIO {
		return cur.value(m)
	}
	if prev.at.IsZero() {
		return 0
	}
	dt := cur.at.Sub(prev.at).Seconds()
	if dt <= 0 {
		return 0
	}
	// 累计计数器单调递增;若设备重置导致回绕,差为负则按 0 处理。
	if cur.diskIOBytes < prev.diskIOBytes {
		return 0
	}
	return float64(cur.diskIOBytes-prev.diskIOBytes) / dt
}

// firing 报告规则在给定实测值下是否处于触发条件(未计入持续时间)。
func (r Rule) firing(value float64) bool {
	return Comparator(r.Comparator).compare(value, r.Threshold)
}

// validateRule 校验规则字段合法性。
func validateRule(r Rule) error {
	if !validMetric(Metric(r.Metric)) {
		return fmt.Errorf("alert: unknown metric %q", r.Metric)
	}
	if !validComparator(Comparator(r.Comparator)) {
		return fmt.Errorf("alert: unknown comparator %q", r.Comparator)
	}
	if r.DurationSec < 0 {
		return fmt.Errorf("alert: duration_sec must be >= 0")
	}
	if r.ChannelID <= 0 {
		return fmt.Errorf("alert: channel_id required")
	}
	if r.Name == "" {
		return fmt.Errorf("alert: name required")
	}
	return nil
}
