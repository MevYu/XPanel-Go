package system

import "github.com/shirou/gopsutil/v3/disk"

// DiskPartition 是单个挂载点的容量与使用率。字节单位为 bytes,UsedPercent 为 0-100。
type DiskPartition struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	Fstype      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

// DiskPartitions 列出物理分区及各自使用情况。某分区取用量失败时跳过该项,不整体报错。
func DiskPartitions() ([]DiskPartition, error) {
	parts, err := disk.Partitions(false)
	if err != nil {
		return nil, err
	}
	result := make([]DiskPartition, 0, len(parts))
	// 同一物理设备可被多个挂载点(容器内大量 bind mount)重复列出,按 device 去重,只留首个(通常是主挂载)。
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		if seen[p.Device] {
			continue
		}
		u, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		seen[p.Device] = true
		result = append(result, DiskPartition{
			Device:      p.Device,
			Mountpoint:  p.Mountpoint,
			Fstype:      p.Fstype,
			Total:       u.Total,
			Used:        u.Used,
			Free:        u.Free,
			UsedPercent: u.UsedPercent,
		})
	}
	return result, nil
}
