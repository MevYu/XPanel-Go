package alert

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockSender 记录发送调用,隔离真实网络。
type mockSender struct {
	mu    sync.Mutex
	calls []Notification
	err   error
}

func (s *mockSender) Send(_ context.Context, _ Channel, _ string, n Notification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.calls = append(s.calls, n)
	return nil
}

func (s *mockSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func newTestStore(t *testing.T) *alertStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	cryp, err := newCryptor("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	ss, err := newAlertStore(st, cryp)
	if err != nil {
		t.Fatalf("newAlertStore: %v", err)
	}
	return ss
}

// seedRule 建一个 email 渠道 + 一条规则,返回规则 id。
func seedRule(t *testing.T, ss *alertStore, r Rule) int64 {
	t.Helper()
	chID, err := ss.createChannel(Channel{Name: "ch", Kind: ChannelEmail, SMTPHost: "h", SMTPPort: 25, SMTPTo: "a@b", Secret: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	r.ChannelID = chID
	r.Enabled = true
	id, err := ss.createRule(r)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// testEvaluator 返回带 mock sender 与可控时钟的 evaluator。
func testEvaluator(ss *alertStore, mock *mockSender, now *time.Time) *evaluator {
	ev := newEvaluator(ss)
	ev.now = func() time.Time { return *now }
	ev.resolve = func(ChannelKind) (Sender, error) { return mock, nil }
	return ev
}

func TestEvaluateTriggersOverThreshold(t *testing.T) {
	ss := newTestStore(t)
	seedRule(t, ss, Rule{Name: "cpu", Metric: "cpu", Comparator: "gt", Threshold: 80})
	mock := &mockSender{}
	now := time.Unix(1000, 0)
	ev := testEvaluator(ss, mock, &now)

	// 90 > 80, duration 0 → 立即触发。
	sent := ev.evaluateSample(context.Background(), sample{cpu: 90})
	if sent != 1 {
		t.Fatalf("expected 1 notification, got %d", sent)
	}
	if mock.count() != 1 {
		t.Fatalf("sender called %d times, want 1", mock.count())
	}
	hist, _ := ss.listHistory(10)
	if len(hist) != 1 || !hist[0].Notified {
		t.Fatalf("expected 1 notified history entry, got %+v", hist)
	}
}

func TestEvaluateNoTriggerUnderThreshold(t *testing.T) {
	ss := newTestStore(t)
	seedRule(t, ss, Rule{Name: "cpu", Metric: "cpu", Comparator: "gt", Threshold: 80})
	mock := &mockSender{}
	now := time.Unix(1000, 0)
	ev := testEvaluator(ss, mock, &now)

	if sent := ev.evaluateSample(context.Background(), sample{cpu: 50}); sent != 0 {
		t.Fatalf("expected 0 notifications, got %d", sent)
	}
	if h, _ := ss.listHistory(10); len(h) != 0 {
		t.Fatalf("expected no history, got %d", len(h))
	}
}

func TestEvaluateDurationGating(t *testing.T) {
	ss := newTestStore(t)
	seedRule(t, ss, Rule{Name: "cpu", Metric: "cpu", Comparator: "gt", Threshold: 80, DurationSec: 60})
	mock := &mockSender{}
	now := time.Unix(1000, 0)
	ev := testEvaluator(ss, mock, &now)
	ctx := context.Background()

	// 首次超阈值:开始计时,未达 60s,不触发。
	if sent := ev.evaluateSample(ctx, sample{cpu: 90}); sent != 0 {
		t.Fatalf("first over-threshold should not fire (duration), got %d", sent)
	}
	// 30s 后仍超阈值:仍不到 60s。
	now = now.Add(30 * time.Second)
	if sent := ev.evaluateSample(ctx, sample{cpu: 90}); sent != 0 {
		t.Fatalf("at 30s should not fire, got %d", sent)
	}
	// 70s 后:超过 60s,触发。
	now = time.Unix(1000, 0).Add(70 * time.Second)
	if sent := ev.evaluateSample(ctx, sample{cpu: 90}); sent != 1 {
		t.Fatalf("at 70s should fire once, got %d", sent)
	}
}

func TestEvaluateDurationResetsOnRecovery(t *testing.T) {
	ss := newTestStore(t)
	seedRule(t, ss, Rule{Name: "cpu", Metric: "cpu", Comparator: "gt", Threshold: 80, DurationSec: 60})
	mock := &mockSender{}
	now := time.Unix(1000, 0)
	ev := testEvaluator(ss, mock, &now)
	ctx := context.Background()

	ev.evaluateSample(ctx, sample{cpu: 90}) // start timer
	now = now.Add(30 * time.Second)
	ev.evaluateSample(ctx, sample{cpu: 50}) // recover → timer reset
	now = now.Add(40 * time.Second)         // 70s since first, but timer was reset
	if sent := ev.evaluateSample(ctx, sample{cpu: 90}); sent != 0 {
		t.Fatalf("timer should have reset on recovery, got %d", sent)
	}
}

func TestEvaluateSilenceDedup(t *testing.T) {
	ss := newTestStore(t)
	if err := ss.saveSettings(Settings{IntervalSec: 30, SilenceSec: 300}); err != nil {
		t.Fatal(err)
	}
	seedRule(t, ss, Rule{Name: "cpu", Metric: "cpu", Comparator: "gt", Threshold: 80})
	mock := &mockSender{}
	now := time.Unix(1000, 0)
	ev := testEvaluator(ss, mock, &now)
	ctx := context.Background()

	// 第一次触发 → 发通知。
	if sent := ev.evaluateSample(ctx, sample{cpu: 90}); sent != 1 {
		t.Fatalf("first fire should notify, got %d", sent)
	}
	// 静默期内(100s < 300s)再次超阈值 → 去重,不发,但记历史。
	now = now.Add(100 * time.Second)
	if sent := ev.evaluateSample(ctx, sample{cpu: 95}); sent != 0 {
		t.Fatalf("within silence window should not notify, got %d", sent)
	}
	// 静默期过后(400s > 300s)再次超阈值 → 重新发。
	now = time.Unix(1000, 0).Add(400 * time.Second)
	if sent := ev.evaluateSample(ctx, sample{cpu: 95}); sent != 1 {
		t.Fatalf("after silence window should notify again, got %d", sent)
	}
	if mock.count() != 2 {
		t.Fatalf("sender should have been called twice, got %d", mock.count())
	}
	// 历史应有 3 条(2 发 + 1 静默)。
	if h, _ := ss.listHistory(10); len(h) != 3 {
		t.Fatalf("expected 3 history entries, got %d", len(h))
	}
}

func TestEvaluateDisabledRuleIgnored(t *testing.T) {
	ss := newTestStore(t)
	chID, _ := ss.createChannel(Channel{Name: "ch", Kind: ChannelEmail, SMTPTo: "a@b"})
	if _, err := ss.createRule(Rule{Name: "cpu", Metric: "cpu", Comparator: "gt", Threshold: 80, ChannelID: chID, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	mock := &mockSender{}
	now := time.Unix(1000, 0)
	ev := testEvaluator(ss, mock, &now)
	if sent := ev.evaluateSample(context.Background(), sample{cpu: 99}); sent != 0 {
		t.Fatalf("disabled rule should not fire, got %d", sent)
	}
}

func TestEvaluateSendFailureRecordedNotNotified(t *testing.T) {
	ss := newTestStore(t)
	seedRule(t, ss, Rule{Name: "cpu", Metric: "cpu", Comparator: "gt", Threshold: 80})
	mock := &mockSender{err: fmt.Errorf("smtp down")}
	now := time.Unix(1000, 0)
	ev := testEvaluator(ss, mock, &now)

	if sent := ev.evaluateSample(context.Background(), sample{cpu: 90}); sent != 0 {
		t.Fatalf("failed send should count 0 sent, got %d", sent)
	}
	h, _ := ss.listHistory(10)
	if len(h) != 1 || h[0].Notified {
		t.Fatalf("expected 1 history entry marked not notified, got %+v", h)
	}
}
