package antitamper

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *atStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	as, err := newATStore(st)
	if err != nil {
		t.Fatalf("newATStore: %v", err)
	}
	return as
}

func TestDefaultSettingsSeeded(t *testing.T) {
	as := newTestStore(t)
	s, err := as.getSettings()
	if err != nil {
		t.Fatal(err)
	}
	if s.IntervalSec != 300 || len(s.ProtectedDirs) == 0 {
		t.Fatalf("defaults not seeded: %+v", s)
	}
}

func TestPutGetSettingsRoundTrip(t *testing.T) {
	as := newTestStore(t)
	in := Settings{
		ProtectedDirs: []string{"/etc/nginx", "/www/site"},
		ExcludeRules:  []string{"*.log"},
		IntervalSec:   60,
		Paused:        true,
	}
	if err := as.putSettings(in); err != nil {
		t.Fatal(err)
	}
	got, err := as.getSettings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ProtectedDirs) != 2 || got.IntervalSec != 60 || !got.Paused {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestBaselineReplaceAndRead(t *testing.T) {
	as := newTestStore(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "x")
	states, _ := ScanTree(context.Background(), root, nil)
	if err := as.replaceBaseline(states); err != nil {
		t.Fatal(err)
	}
	got, err := as.baseline()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 baseline entry, got %d", len(got))
	}
}

func TestRecordAndListEvents(t *testing.T) {
	as := newTestStore(t)
	changes := []Change{
		{Path: "/a", Type: ChangeModified, OldHash: "o", NewHash: "n"},
		{Path: "/b", Type: ChangeDeleted, OldHash: "o"},
	}
	if err := as.recordEvents(changes); err != nil {
		t.Fatal(err)
	}
	evs, err := as.listEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
}

func TestApplyChangesUpdatesBaseline(t *testing.T) {
	as := newTestStore(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "mod.txt"), "before")
	base, _ := ScanTree(context.Background(), root, nil)
	as.replaceBaseline(base)

	writeFile(t, filepath.Join(root, "mod.txt"), "after")
	writeFile(t, filepath.Join(root, "new.txt"), "added")
	cur, _ := ScanTree(context.Background(), root, nil)
	changes := Diff(base, cur)

	if err := as.applyChanges(cur, changes); err != nil {
		t.Fatal(err)
	}
	// after applying, a re-diff against stored baseline must be clean
	newBase, _ := as.baseline()
	if c := Diff(newBase, cur); len(c) != 0 {
		t.Fatalf("baseline not updated, residual changes: %+v", c)
	}
}
