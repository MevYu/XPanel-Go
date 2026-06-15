package sitemonitor

import (
	"testing"
	"time"
)

func mkEntry(ip, url, ua string, status int, bytes int64, t time.Time) Entry {
	return Entry{IP: ip, URL: url, UserAgent: ua, Status: status, Bytes: bytes, Time: t, Host: "site.test"}
}

func TestAggregatorOverview(t *testing.T) {
	base := time.Date(2023, 10, 10, 10, 0, 0, 0, time.UTC)
	entries := []Entry{
		mkEntry("1.1.1.1", "/a", "UA1", 200, 100, base),
		mkEntry("1.1.1.1", "/a", "UA1", 200, 100, base),
		mkEntry("2.2.2.2", "/b", "UA2", 404, 50, base),
		mkEntry("3.3.3.3", "/a", "UA1", 500, 10, base),
		mkEntry("2.2.2.2", "/c", "UA2", 301, 0, base),
	}
	agg := NewAggregator(TimeRange{})
	for _, e := range entries {
		agg.Add(e)
	}
	rep := agg.Report(10)

	if rep.TotalRequests != 5 {
		t.Errorf("total = %d", rep.TotalRequests)
	}
	if rep.TotalBytes != 260 {
		t.Errorf("bytes = %d", rep.TotalBytes)
	}
	if rep.UniqueIPs != 3 {
		t.Errorf("uv = %d", rep.UniqueIPs)
	}
	if rep.Status.XX2 != 2 || rep.Status.XX3 != 1 || rep.Status.XX4 != 1 || rep.Status.XX5 != 1 {
		t.Errorf("status = %+v", rep.Status)
	}
	if len(rep.TopURLs) == 0 || rep.TopURLs[0].Key != "/a" || rep.TopURLs[0].Count != 3 {
		t.Errorf("top urls = %+v", rep.TopURLs)
	}
	if rep.TopIPs[0].Count != 2 { // 1.1.1.1 and 2.2.2.2 both have 2; key tiebreak ascending
		t.Errorf("top ips = %+v", rep.TopIPs)
	}
}

func TestAggregatorTimeRangeFilter(t *testing.T) {
	jan := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	feb := time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)
	mar := time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC)
	entries := []Entry{
		mkEntry("1.1.1.1", "/a", "UA", 200, 10, jan),
		mkEntry("2.2.2.2", "/b", "UA", 200, 10, feb),
		mkEntry("3.3.3.3", "/c", "UA", 200, 10, mar),
	}
	rng := TimeRange{From: feb.Add(-time.Hour), To: feb.Add(time.Hour)}
	agg := NewAggregator(rng)
	for _, e := range entries {
		agg.Add(e)
	}
	rep := agg.Report(10)
	if rep.TotalRequests != 1 {
		t.Errorf("range filter expected 1, got %d", rep.TotalRequests)
	}
	if rep.UniqueIPs != 1 {
		t.Errorf("uv = %d", rep.UniqueIPs)
	}
}

func TestAggregatorSites(t *testing.T) {
	base := time.Now()
	agg := NewAggregator(TimeRange{})
	agg.Add(Entry{IP: "1.1.1.1", Host: "a.com", Status: 200, Bytes: 100, Time: base})
	agg.Add(Entry{IP: "1.1.1.1", Host: "a.com", Status: 200, Bytes: 100, Time: base})
	agg.Add(Entry{IP: "2.2.2.2", Host: "b.com", Status: 200, Bytes: 50, Time: base})
	sites := agg.Sites()
	if len(sites) != 2 {
		t.Fatalf("sites = %d", len(sites))
	}
	if sites[0].Host != "a.com" || sites[0].Requests != 2 || sites[0].Bytes != 200 {
		t.Errorf("top site = %+v", sites[0])
	}
}

func TestTrendHourly(t *testing.T) {
	h10 := time.Date(2023, 10, 10, 10, 30, 0, 0, time.UTC)
	h10b := time.Date(2023, 10, 10, 10, 45, 0, 0, time.UTC)
	h11 := time.Date(2023, 10, 10, 11, 5, 0, 0, time.UTC)
	entries := []Entry{
		{Time: h10, Bytes: 10, Status: 200},
		{Time: h10b, Bytes: 20, Status: 200},
		{Time: h11, Bytes: 5, Status: 200},
	}
	pts := Trend(entries, TimeRange{}, "hour")
	if len(pts) != 2 {
		t.Fatalf("expected 2 hourly buckets, got %d (%+v)", len(pts), pts)
	}
	if pts[0].Requests != 2 || pts[0].Bytes != 30 {
		t.Errorf("bucket0 = %+v", pts[0])
	}
	if pts[1].Requests != 1 {
		t.Errorf("bucket1 = %+v", pts[1])
	}
}

func TestTrendDaily(t *testing.T) {
	d1 := time.Date(2023, 10, 10, 1, 0, 0, 0, time.UTC)
	d1b := time.Date(2023, 10, 10, 23, 0, 0, 0, time.UTC)
	d2 := time.Date(2023, 10, 11, 5, 0, 0, 0, time.UTC)
	pts := Trend([]Entry{{Time: d1}, {Time: d1b}, {Time: d2}}, TimeRange{}, "day")
	if len(pts) != 2 {
		t.Fatalf("expected 2 daily buckets, got %d", len(pts))
	}
	if pts[0].Requests != 2 {
		t.Errorf("day0 = %+v", pts[0])
	}
}

func TestTopCountsLimit(t *testing.T) {
	m := map[string]int64{"a": 5, "b": 4, "c": 3, "d": 2}
	out := topCounts(m, 2)
	if len(out) != 2 || out[0].Key != "a" || out[1].Key != "b" {
		t.Errorf("top2 = %+v", out)
	}
}
