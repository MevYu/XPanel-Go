package system

import (
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// NetInterface 是单网卡的累计流量计数。速率由前端按相邻采样差分得到。
type NetInterface struct {
	Name        string `json:"name"`
	BytesRecv   uint64 `json:"bytes_recv"`
	BytesSent   uint64 `json:"bytes_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	PacketsSent uint64 `json:"packets_sent"`
}

// DiskIO 是单块设备的累计读写计数。速率由前端差分得到。
type DiskIO struct {
	Name       string `json:"name"`
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
	ReadCount  uint64 `json:"read_count"`
	WriteCount uint64 `json:"write_count"`
}

// LoadAvg 是 1/5/15 分钟系统负载(Linux/Unix)。
type LoadAvg struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// MemDetail 是内存细分,字节单位。Swap* 来自 SwapMemory,其余来自 VirtualMemory。
type MemDetail struct {
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
	Available uint64 `json:"available"`
	Free      uint64 `json:"free"`
	Cached    uint64 `json:"cached"`
	Buffers   uint64 `json:"buffers"`
	SwapTotal uint64 `json:"swap_total"`
	SwapUsed  uint64 `json:"swap_used"`
	SwapFree  uint64 `json:"swap_free"`
}

// DetailMetrics 是一次细化系统快照,补充 Snapshot 之外的指标。
type DetailMetrics struct {
	CPUPerCore []float64      `json:"cpu_per_core"`
	Load       LoadAvg        `json:"load"`
	Memory     MemDetail      `json:"memory"`
	Network    []NetInterface `json:"network"`
	DiskIO     []DiskIO       `json:"disk_io"`
	UptimeSec  uint64         `json:"uptime_sec"`
	BootTime   uint64         `json:"boot_time"`
}

// DetailSnapshot 采集细化指标。CPU 每核用 100ms 采样窗口。
// load.Avg 在不支持的平台会报错,此时 Load 留零值不致命。
func DetailSnapshot() (DetailMetrics, error) {
	var d DetailMetrics

	perCore, err := cpu.Percent(100*time.Millisecond, true)
	if err != nil {
		return d, err
	}
	d.CPUPerCore = perCore

	if avg, err := load.Avg(); err == nil {
		d.Load = LoadAvg{Load1: avg.Load1, Load5: avg.Load5, Load15: avg.Load15}
	}

	vm, err := mem.VirtualMemory()
	if err != nil {
		return d, err
	}
	d.Memory = MemDetail{
		Total:     vm.Total,
		Used:      vm.Used,
		Available: vm.Available,
		Free:      vm.Free,
		Cached:    vm.Cached,
		Buffers:   vm.Buffers,
	}
	if sw, err := mem.SwapMemory(); err == nil {
		d.Memory.SwapTotal = sw.Total
		d.Memory.SwapUsed = sw.Used
		d.Memory.SwapFree = sw.Free
	}

	d.Network, err = networkCounters()
	if err != nil {
		return d, err
	}
	d.DiskIO, err = diskIOCounters()
	if err != nil {
		return d, err
	}

	if up, err := host.Uptime(); err == nil {
		d.UptimeSec = up
	}
	if bt, err := host.BootTime(); err == nil {
		d.BootTime = bt
	}
	return d, nil
}

// networkCounters 返回每网卡累计计数(pernic=true)。
func networkCounters() ([]NetInterface, error) {
	stats, err := net.IOCounters(true)
	if err != nil {
		return nil, err
	}
	out := make([]NetInterface, 0, len(stats))
	for _, s := range stats {
		out = append(out, NetInterface{
			Name:        s.Name,
			BytesRecv:   s.BytesRecv,
			BytesSent:   s.BytesSent,
			PacketsRecv: s.PacketsRecv,
			PacketsSent: s.PacketsSent,
		})
	}
	return out, nil
}

// diskIOCounters 返回每块设备累计读写计数。
func diskIOCounters() ([]DiskIO, error) {
	stats, err := disk.IOCounters()
	if err != nil {
		return nil, err
	}
	out := make([]DiskIO, 0, len(stats))
	for name, s := range stats {
		out = append(out, DiskIO{
			Name:       name,
			ReadBytes:  s.ReadBytes,
			WriteBytes: s.WriteBytes,
			ReadCount:  s.ReadCount,
			WriteCount: s.WriteCount,
		})
	}
	return out, nil
}
