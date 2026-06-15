package system

import (
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// Metrics 是一次系统资源快照。字节单位为 bytes,CPUPercent 为 0-100。
type Metrics struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemTotal   uint64  `json:"mem_total"`
	MemUsed    uint64  `json:"mem_used"`
	DiskTotal  uint64  `json:"disk_total"`
	DiskUsed   uint64  `json:"disk_used"`
}

// Snapshot 采集一次 CPU/内存/根分区磁盘使用。CPU 用 100ms 采样窗口。
func Snapshot() (Metrics, error) {
	var m Metrics
	cpuPercents, err := cpu.Percent(100*time.Millisecond, false)
	if err != nil {
		return m, err
	}
	if len(cpuPercents) > 0 {
		m.CPUPercent = cpuPercents[0]
	}
	vm, err := mem.VirtualMemory()
	if err != nil {
		return m, err
	}
	m.MemTotal, m.MemUsed = vm.Total, vm.Used
	du, err := disk.Usage("/")
	if err != nil {
		return m, err
	}
	m.DiskTotal, m.DiskUsed = du.Total, du.Used
	return m, nil
}
