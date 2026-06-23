package system

import (
	"context"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
)

// cpuInfoCache 缓存静态 CPU 信息。型号与核数运行期不变,首次成功采集后复用,
// 避免每次 sysinfo 请求都调 cpu.Info()(有 /proc 解析开销)。
var cpuInfoCache struct {
	once     sync.Once
	model    string
	physical int
	logical  int
}

// CPUInfo 返回 CPU 型号、物理核数、逻辑核数。结果首次采集后缓存。
// 任一来源取失败降级为零值(空串/0),绝不报错,供 sysinfo 端点安全调用。
func CPUInfo() (model string, physical, logical int) {
	cpuInfoCache.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if infos, err := cpu.InfoWithContext(ctx); err == nil && len(infos) > 0 {
			cpuInfoCache.model = infos[0].ModelName
		}
		if n, err := cpu.CountsWithContext(ctx, false); err == nil {
			cpuInfoCache.physical = n
		}
		if n, err := cpu.CountsWithContext(ctx, true); err == nil {
			cpuInfoCache.logical = n
		}
	})
	return cpuInfoCache.model, cpuInfoCache.physical, cpuInfoCache.logical
}
