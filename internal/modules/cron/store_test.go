package cron

import (
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *cronStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	cs, err := newCronStore(st)
	if err != nil {
		t.Fatalf("new cron store: %v", err)
	}
	return cs
}

func TestCronStoreCRUD(t *testing.T) {
	cs := newTestStore(t)

	uid := int64(7)
	id, err := cs.create(Job{
		Expr: "0 3 * * *", Type: taskCommand, Payload: payload{Command: "/bin/backup.sh"},
		Command: "/bin/backup.sh", Comment: "nightly", Enabled: true, CreatedBy: &uid,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	j, err := cs.get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if j.Expr != "0 3 * * *" || j.Command != "/bin/backup.sh" || !j.Enabled {
		t.Errorf("unexpected job: %+v", j)
	}
	if j.Type != taskCommand || j.Payload.Command != "/bin/backup.sh" {
		t.Errorf("type/payload not persisted: %+v", j)
	}
	if j.CreatedBy == nil || *j.CreatedBy != 7 {
		t.Errorf("created_by not persisted: %+v", j.CreatedBy)
	}

	if err := cs.update(id, Job{
		Expr: "*/5 * * * *", Type: taskURL, Payload: payload{URL: "http://x/y", Timeout: 10},
		Command: "curl ...", Comment: "changed",
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	j, _ = cs.get(id)
	if j.Expr != "*/5 * * * *" || j.Type != taskURL || j.Payload.URL != "http://x/y" || j.Comment != "changed" {
		t.Errorf("update not applied: %+v", j)
	}

	if err := cs.setEnabled(id, false); err != nil {
		t.Fatalf("setEnabled: %v", err)
	}
	j, _ = cs.get(id)
	if j.Enabled {
		t.Error("job should be disabled")
	}

	list, _ := cs.list()
	if len(list) != 1 {
		t.Fatalf("expected 1 job, got %d", len(list))
	}

	if err := cs.delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	list, _ = cs.list()
	if len(list) != 0 {
		t.Errorf("expected 0 jobs after delete, got %d", len(list))
	}
}

func TestCronStoreEnabledFiltersDisabled(t *testing.T) {
	cs := newTestStore(t)
	on, _ := cs.create(Job{Expr: "* * * * *", Command: "a", Enabled: true})
	_, _ = cs.create(Job{Expr: "* * * * *", Command: "b", Enabled: false})

	en, err := cs.enabled()
	if err != nil {
		t.Fatalf("enabled: %v", err)
	}
	if len(en) != 1 || en[0].ID != on {
		t.Errorf("enabled() should return only enabled jobs, got %+v", en)
	}
}

func TestNewCronStoreIdempotent(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := newCronStore(st); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := newCronStore(st); err != nil {
		t.Fatalf("second (table already exists) should be idempotent: %v", err)
	}
}
