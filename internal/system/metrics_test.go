package system

import "testing"

func TestSnapshotReturnsPlausibleValues(t *testing.T) {
	s, err := Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if s.MemTotal == 0 {
		t.Error("MemTotal should be > 0")
	}
	if s.CPUPercent < 0 || s.CPUPercent > 100 {
		t.Errorf("CPUPercent out of range: %f", s.CPUPercent)
	}
	if s.DiskTotal == 0 {
		t.Error("DiskTotal should be > 0")
	}
}
