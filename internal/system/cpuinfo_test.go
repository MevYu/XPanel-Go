package system

import "testing"

// TestCPUInfo 验证采集不 panic,逻辑核数在测试运行时应 >= 1。
// 型号可能为空(容器/特殊平台),物理核数允许为 0(降级),只断言不崩溃。
func TestCPUInfo(t *testing.T) {
	model, physical, logical := CPUInfo()
	if logical < 1 {
		t.Errorf("logical cores = %d, want >= 1", logical)
	}
	if physical < 0 {
		t.Errorf("physical cores = %d, want >= 0", physical)
	}
	_ = model
}

// TestCPUInfoCached 验证二次调用返回与首次一致(缓存语义)。
func TestCPUInfoCached(t *testing.T) {
	m1, p1, l1 := CPUInfo()
	m2, p2, l2 := CPUInfo()
	if m1 != m2 || p1 != p2 || l1 != l2 {
		t.Errorf("cached CPUInfo mismatch: (%q,%d,%d) vs (%q,%d,%d)", m1, p1, l1, m2, p2, l2)
	}
}
