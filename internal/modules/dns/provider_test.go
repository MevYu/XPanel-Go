package dns

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestMockProviderHealthyNeedsCreds(t *testing.T) {
	if err := newMockProvider("").healthy(); err == nil {
		t.Error("mock provider without creds should be unhealthy")
	}
	if err := newMockProvider("token").healthy(); err != nil {
		t.Errorf("mock provider with creds should be healthy, got %v", err)
	}
}

func TestMockProviderApplyStores(t *testing.T) {
	p := newMockProvider("tok")
	recs := []Record{{ID: 1, Name: "www", Type: "A", Value: "1.2.3.4", TTL: 300}}
	if err := p.apply(context.Background(), "example.com", recs); err != nil {
		t.Fatal(err)
	}
	if got := p.applied["example.com"]; len(got) != 1 || got[0].Value != "1.2.3.4" {
		t.Errorf("apply did not store records: %+v", got)
	}
}

func TestRenderZoneSafe(t *testing.T) {
	recs := []Record{
		{Name: "@", Type: "A", Value: "1.2.3.4", TTL: 300},
		{Name: "www", Type: "CNAME", Value: "example.com.", TTL: 300},
		{Name: "mail", Type: "MX", Value: "mail.example.com.", TTL: 300, Priority: 10},
		{Name: "@", Type: "TXT", Value: "v=spf1 -all", TTL: 300},
	}
	out, err := renderZone("example.com", recs)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SOA", "IN\tA\t1.2.3.4", "IN\tMX\t10 mail.example.com.", "IN\tTXT\t\"v=spf1 -all\""} {
		if !strings.Contains(out, want) {
			t.Errorf("zone missing %q\n%s", want, out)
		}
	}
}

func TestRenderRecordRejectsInjection(t *testing.T) {
	bad := []Record{
		{Name: "www\nevil", Type: "A", Value: "1.2.3.4", TTL: 300},
		{Name: "www", Type: "A", Value: "1.2.3.4\nevil IN A 6.6.6.6", TTL: 300},
		{Name: "www", Type: "NOTATYPE", Value: "x", TTL: 300},
	}
	for _, r := range bad {
		if _, err := renderRecord(r); err == nil {
			t.Errorf("renderRecord(%+v) should reject injection", r)
		}
	}
}

func TestBindApplyWritesAndReloads(t *testing.T) {
	dir := t.TempDir()
	reloaded := ""
	b := newBindBackend(dir)
	b.reload = func(_ context.Context, zone string) error { reloaded = zone; return nil }
	recs := []Record{{Name: "www", Type: "A", Value: "1.2.3.4", TTL: 300}}
	if err := b.apply(context.Background(), "example.com", recs); err != nil {
		t.Fatal(err)
	}
	if reloaded != "example.com" {
		t.Errorf("reload not called with zone, got %q", reloaded)
	}
	data, err := os.ReadFile(b.zonePath("example.com"))
	if err != nil {
		t.Fatalf("zone file not written: %v", err)
	}
	if !strings.Contains(string(data), "1.2.3.4") {
		t.Errorf("zone file missing record:\n%s", data)
	}
}

func TestBindApplyRejectsBadZone(t *testing.T) {
	b := newBindBackend(t.TempDir())
	b.reload = func(context.Context, string) error { return nil }
	if err := b.apply(context.Background(), "../etc/passwd", nil); err == nil {
		t.Error("bind apply must reject unsafe zone name")
	}
}
