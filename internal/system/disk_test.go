package system

import "testing"

func TestDiskPartitionsReturnsSaneSlice(t *testing.T) {
	parts, err := DiskPartitions()
	if err != nil {
		t.Fatalf("DiskPartitions: %v", err)
	}
	if parts == nil {
		t.Fatal("DiskPartitions returned nil slice")
	}
	for i, p := range parts {
		if p.Mountpoint == "" {
			t.Errorf("partition[%d] has empty mountpoint: %+v", i, p)
		}
		if p.UsedPercent < 0 || p.UsedPercent > 100 {
			t.Errorf("partition[%d] UsedPercent out of range: %f", i, p.UsedPercent)
		}
	}
}
