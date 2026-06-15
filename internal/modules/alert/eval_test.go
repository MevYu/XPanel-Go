package alert

import (
	"testing"
	"time"
)

func TestComparatorCompare(t *testing.T) {
	cases := []struct {
		cmp        Comparator
		val, thr   float64
		wantFiring bool
	}{
		{GreaterThan, 90, 80, true},
		{GreaterThan, 70, 80, false},
		{GreaterThan, 80, 80, false}, // strict
		{LessThan, 5, 10, true},
		{LessThan, 15, 10, false},
	}
	for _, c := range cases {
		if got := c.cmp.compare(c.val, c.thr); got != c.wantFiring {
			t.Errorf("%s.compare(%v,%v) = %v, want %v", c.cmp, c.val, c.thr, got, c.wantFiring)
		}
	}
}

func TestValidateRule(t *testing.T) {
	ok := Rule{Name: "cpu high", Metric: "cpu", Comparator: "gt", Threshold: 80, ChannelID: 1}
	if err := validateRule(ok); err != nil {
		t.Errorf("valid rule rejected: %v", err)
	}
	bad := []Rule{
		{Name: "x", Metric: "bogus", Comparator: "gt", ChannelID: 1},
		{Name: "x", Metric: "cpu", Comparator: "ge", ChannelID: 1},
		{Name: "x", Metric: "cpu", Comparator: "gt", ChannelID: 0},
		{Name: "", Metric: "cpu", Comparator: "gt", ChannelID: 1},
		{Name: "x", Metric: "cpu", Comparator: "gt", ChannelID: 1, DurationSec: -1},
	}
	for i, r := range bad {
		if err := validateRule(r); err == nil {
			t.Errorf("bad rule %d accepted", i)
		}
	}
}

func TestSampleValue(t *testing.T) {
	s := sample{cpu: 12, memory: 34, disk: 56, load1: 1.5, diskIOBytes: 1000}
	cases := map[Metric]float64{
		MetricCPU: 12, MetricMemory: 34, MetricDisk: 56, MetricLoad: 1.5, MetricDiskIO: 1000,
	}
	for m, want := range cases {
		if got := s.value(m); got != want {
			t.Errorf("value(%s) = %v, want %v", m, got, want)
		}
	}
}

func TestMetricValueDiskIORate(t *testing.T) {
	t0 := time.Unix(1000, 0)
	prev := sample{diskIOBytes: 1000, at: t0}
	cur := sample{diskIOBytes: 5000, at: t0.Add(2 * time.Second)}
	// (5000-1000)/2s = 2000 bytes/s
	if got := metricValue(MetricDiskIO, cur, prev); got != 2000 {
		t.Errorf("disk_io rate = %v, want 2000", got)
	}
}

func TestMetricValueDiskIONoPrev(t *testing.T) {
	cur := sample{diskIOBytes: 5000, at: time.Unix(1000, 0)}
	if got := metricValue(MetricDiskIO, cur, sample{}); got != 0 {
		t.Errorf("disk_io with no prev = %v, want 0", got)
	}
}

func TestMetricValueDiskIOCounterReset(t *testing.T) {
	t0 := time.Unix(1000, 0)
	prev := sample{diskIOBytes: 9000, at: t0}
	cur := sample{diskIOBytes: 100, at: t0.Add(time.Second)} // counter went backwards
	if got := metricValue(MetricDiskIO, cur, prev); got != 0 {
		t.Errorf("disk_io after counter reset = %v, want 0", got)
	}
}

func TestPct(t *testing.T) {
	if got := pct(50, 200); got != 25 {
		t.Errorf("pct(50,200) = %v, want 25", got)
	}
	if got := pct(1, 0); got != 0 {
		t.Errorf("pct with zero total = %v, want 0", got)
	}
}
