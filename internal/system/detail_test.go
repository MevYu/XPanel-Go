package system

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestDetailSnapshot(t *testing.T) {
	d, err := DetailSnapshot()
	if err != nil {
		t.Fatalf("DetailSnapshot: %v", err)
	}

	if len(d.CPUPerCore) == 0 {
		t.Error("CPUPerCore should have at least one core")
	}
	for i, p := range d.CPUPerCore {
		if p < 0 || p > 100 {
			t.Errorf("core %d percent out of range: %f", i, p)
		}
	}

	if d.CPUIOWait < 0 || d.CPUIOWait > 100 {
		t.Errorf("CPUIOWait out of range: %f", d.CPUIOWait)
	}

	if d.Memory.Total == 0 {
		t.Error("Memory.Total should be > 0")
	}

	if len(d.Network) == 0 {
		t.Error("expected at least one network interface")
	}

	if d.UptimeSec == 0 {
		t.Error("UptimeSec should be > 0")
	}
	if d.BootTime == 0 {
		t.Error("BootTime should be > 0")
	}

	// Load 仅 Linux/Unix 保证非零负载语义;此处只断言非负。
	if runtime.GOOS == "linux" {
		if d.Load.Load1 < 0 || d.Load.Load5 < 0 || d.Load.Load15 < 0 {
			t.Errorf("load avg negative: %+v", d.Load)
		}
	}

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"cpu_iowait_percent"`) {
		t.Errorf("cpu_iowait_percent missing from JSON: %s", b)
	}
}
