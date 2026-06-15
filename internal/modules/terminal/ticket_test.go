package terminal

import (
	"testing"
	"time"
)

func TestTicketIssueAndConsume(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	ts := newTicketStore(30*time.Second, clock)

	tok := ts.issue(42, "operator")
	if tok == "" {
		t.Fatal("issue must return a non-empty token")
	}

	sess, ok := ts.consume(tok)
	if !ok {
		t.Fatal("freshly issued ticket must be consumable")
	}
	if sess.userID != 42 || sess.role != "operator" {
		t.Fatalf("consumed session mismatch: %+v", sess)
	}
}

func TestTicketSingleUse(t *testing.T) {
	ts := newTicketStore(30*time.Second, time.Now)
	tok := ts.issue(1, "admin")

	if _, ok := ts.consume(tok); !ok {
		t.Fatal("first consume must succeed")
	}
	if _, ok := ts.consume(tok); ok {
		t.Fatal("second consume of same ticket must fail (single-use)")
	}
}

func TestTicketExpiry(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	ts := newTicketStore(30*time.Second, clock)

	tok := ts.issue(7, "operator")
	now = now.Add(31 * time.Second) // 越过 TTL

	if _, ok := ts.consume(tok); ok {
		t.Fatal("expired ticket must not be consumable")
	}
}

func TestTicketUnknown(t *testing.T) {
	ts := newTicketStore(30*time.Second, time.Now)
	if _, ok := ts.consume("does-not-exist"); ok {
		t.Fatal("unknown ticket must not be consumable")
	}
}

func TestTicketsAreDistinct(t *testing.T) {
	ts := newTicketStore(30*time.Second, time.Now)
	a := ts.issue(1, "admin")
	b := ts.issue(1, "admin")
	if a == b {
		t.Fatal("each issued ticket must be unique")
	}
}

func TestTicketExpiredPurgedOnIssue(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	ts := newTicketStore(30*time.Second, clock)

	ts.issue(1, "admin")
	now = now.Add(31 * time.Second)
	ts.issue(2, "admin") // 触发惰性清理

	if n := ts.len(); n != 1 {
		t.Fatalf("expired ticket should be purged on issue, want 1 live, got %d", n)
	}
}
