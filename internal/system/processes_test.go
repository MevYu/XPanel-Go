package system

import "testing"

func TestTopProcesses(t *testing.T) {
	procs, err := TopProcesses(5)
	if err != nil {
		t.Fatalf("TopProcesses: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("expected at least one process")
	}
	if len(procs) > 5 {
		t.Errorf("TopProcesses(5) returned %d, want <=5", len(procs))
	}
	for _, p := range procs {
		if p.PID <= 0 {
			t.Errorf("invalid pid: %d", p.PID)
		}
		if p.Name == "" {
			t.Errorf("pid %d has empty name", p.PID)
		}
		if p.CPUPercent < 0 {
			t.Errorf("pid %d negative cpu: %f", p.PID, p.CPUPercent)
		}
	}
	// 降序校验
	for i := 1; i < len(procs); i++ {
		if procs[i-1].CPUPercent < procs[i].CPUPercent {
			t.Errorf("not sorted by cpu desc at %d", i)
		}
	}
}

func TestTopProcessesZeroLimit(t *testing.T) {
	procs, err := TopProcesses(0)
	if err != nil {
		t.Fatalf("TopProcesses(0): %v", err)
	}
	if len(procs) != 0 {
		t.Errorf("expected empty, got %d", len(procs))
	}
}
