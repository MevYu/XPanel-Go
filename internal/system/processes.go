package system

import (
	"sort"

	"github.com/shirou/gopsutil/v3/process"
)

// ProcessInfo 是单个进程的只读快照。CPUPercent 为进程生命周期内的平均 CPU 占用。
type ProcessInfo struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float32 `json:"mem_percent"`
	RSS        uint64  `json:"rss"`
}

// TopProcesses 返回按 CPU 占用降序排列的前 limit 个进程。limit<=0 时返回空。
// 单个进程采集失败(已退出/无权限)被跳过,不致命。
func TopProcesses(limit int) ([]ProcessInfo, error) {
	if limit <= 0 {
		return []ProcessInfo{}, nil
	}
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}
	out := make([]ProcessInfo, 0, len(procs))
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		cpuPct, _ := p.CPUPercent()
		memPct, _ := p.MemoryPercent()
		var rss uint64
		if mi, err := p.MemoryInfo(); err == nil && mi != nil {
			rss = mi.RSS
		}
		out = append(out, ProcessInfo{
			PID:        p.Pid,
			Name:       name,
			CPUPercent: cpuPct,
			MemPercent: memPct,
			RSS:        rss,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CPUPercent > out[j].CPUPercent
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
