//go:build fleet

package fleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nats-io/nats.go"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestModule(t *testing.T, role string) (*Module, *int) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	audited := new(int)
	m := New(st, Deps{
		Principal: func(*http.Request) (int64, string) { return 7, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	})
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	return m, audited
}

func do(m *Module, method, target, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	m.Routes(r)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// secret 取出 controller 的 NATS 连接密钥(供测试 agent 连接)。
func (m *Module) testSecret(t *testing.T) string {
	t.Helper()
	s, err := m.ss.getOrCreateSecret(randToken)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	return s
}

// mockAgent 连入 controller NATS,可选回应命令。
type mockAgent struct {
	nc     *nats.Conn
	nodeID string
}

func dialAgent(t *testing.T, m *Module, nodeID string) *mockAgent {
	t.Helper()
	nc, err := nats.Connect(m.ctl.clientURL(), nats.Token(m.testSecret(t)))
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return &mockAgent{nc: nc, nodeID: nodeID}
}

func (a *mockAgent) enroll(t *testing.T, token, tags string) enrollReply {
	t.Helper()
	b, _ := json.Marshal(enrollMsg{Token: token, NodeID: a.nodeID, Name: a.nodeID, Tags: tags, Version: "test"})
	msg, err := a.nc.Request(subjEnroll, b, 2*time.Second)
	if err != nil {
		t.Fatalf("enroll request: %v", err)
	}
	var rep enrollReply
	if err := json.Unmarshal(msg.Data, &rep); err != nil {
		t.Fatalf("enroll reply: %v", err)
	}
	return rep
}

// respondCmd 订阅自己的命令主题,用给定 reply 回应,直到 t 结束。
func (a *mockAgent) respondCmd(t *testing.T, reply cmdReply) {
	t.Helper()
	sub, err := a.nc.Subscribe(cmdSubject(a.nodeID), func(m *nats.Msg) {
		b, _ := json.Marshal(reply)
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("subscribe cmd: %v", err)
	}
	_ = a.nc.Flush()
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

func (a *mockAgent) beat(t *testing.T) {
	t.Helper()
	b, _ := json.Marshal(heartbeatMsg{NodeID: a.nodeID, Version: "test"})
	if err := a.nc.Publish(subjHeartbeat, b); err != nil {
		t.Fatalf("publish hb: %v", err)
	}
	_ = a.nc.Flush()
}

// createEnrollToken 用 admin HTTP 路径生成 token,返回 enroll 部分。
func createEnrollToken(t *testing.T, m *Module) string {
	t.Helper()
	rec := do(m, http.MethodPost, "/enroll-tokens", "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create enroll token: code %d", rec.Code)
	}
	var resp enrollTokenResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	enroll, _, ok := splitToken(resp.Token)
	if !ok {
		t.Fatalf("malformed token %q", resp.Token)
	}
	return enroll
}

func TestMetaSwitchable(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	meta := m.Meta()
	if meta.ID != "fleet" {
		t.Errorf("id = %q, want fleet", meta.ID)
	}
	if meta.AlwaysOn {
		t.Error("fleet must be switchable, not always-on")
	}
}

func TestEnrollTokenOneTime(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	tok := createEnrollToken(t, m)
	agent := dialAgent(t, m, "node-a")

	if rep := agent.enroll(t, tok, ""); !rep.OK {
		t.Fatalf("first enroll rejected: %s", rep.Error)
	}
	if rep := agent.enroll(t, tok, ""); rep.OK {
		t.Error("second enroll with same token must fail (one-time)")
	}
}

func TestUnapprovedNodeReceivesNoCommand(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	tok := createEnrollToken(t, m)
	agent := dialAgent(t, m, "node-pending")
	agent.enroll(t, tok, "")
	agent.respondCmd(t, cmdReply{ExitCode: 0, Output: "ran"})

	// 节点 pending,未审批 → activeTargets 应为空 → job 无目标。
	rec := do(m, http.MethodPost, "/jobs", `{"argv":["echo","hi"],"selector":"all","timeout_sec":2}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create job: code %d body %s", rec.Code, rec.Body.String())
	}
	var resp jobResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Summary.Total != 0 {
		t.Errorf("unapproved node should not be targeted; total = %d", resp.Summary.Total)
	}
}

func TestHeartbeatUpdatesLastSeen(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	tok := createEnrollToken(t, m)
	agent := dialAgent(t, m, "node-hb")
	agent.enroll(t, tok, "")

	before, _ := m.ss.getNode("node-hb")
	time.Sleep(1100 * time.Millisecond)
	agent.beat(t)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := m.ss.getNode("node-hb")
		if n.LastSeen > before.LastSeen {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("heartbeat did not update last_seen")
}

func TestFanOutAggregatesResults(t *testing.T) {
	m, _ := newTestModule(t, "admin")

	// 三个节点:ok(success)、bad(非零退出=failed)、gone(连了但不回应=timeout)。
	specs := []struct {
		id    string
		reply *cmdReply // nil = 不回应
	}{
		{"node-ok", &cmdReply{ExitCode: 0, Output: "ok"}},
		{"node-bad", &cmdReply{ExitCode: 2, Output: "boom"}},
		{"node-gone", nil},
	}
	for _, s := range specs {
		tok := createEnrollToken(t, m)
		a := dialAgent(t, m, s.id)
		a.enroll(t, tok, "")
		if s.reply != nil {
			a.respondCmd(t, *s.reply)
		}
		// 全部审批为 active。
		if rec := do(m, http.MethodPost, "/nodes/"+s.id+"/approve", ""); rec.Code != http.StatusNoContent {
			t.Fatalf("approve %s: code %d", s.id, rec.Code)
		}
	}

	rec := do(m, http.MethodPost, "/jobs", `{"argv":["echo","hi"],"selector":"all","timeout_sec":1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create job: code %d body %s", rec.Code, rec.Body.String())
	}
	var resp jobResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Summary.Total != 3 {
		t.Fatalf("total = %d, want 3", resp.Summary.Total)
	}
	if resp.Summary.Success != 1 || resp.Summary.Failed != 1 || resp.Summary.Timeout != 1 {
		t.Errorf("summary = %+v, want 1/1/1 success/failed/timeout", resp.Summary)
	}

	// GET 聚合应与 POST 一致。
	rec2 := do(m, http.MethodGet, "/jobs/"+itoa(resp.JobID), "")
	if rec2.Code != http.StatusOK {
		t.Fatalf("get job: code %d", rec2.Code)
	}
}

func TestReaderCannotDispatch(t *testing.T) {
	m, _ := newTestModule(t, "operator") // 只读/操作员:非 admin
	rec := do(m, http.MethodPost, "/jobs", `{"argv":["echo","hi"],"selector":"all"}`)
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator POST /jobs: code %d, want 403", rec.Code)
	}
	rec2 := do(m, http.MethodPost, "/enroll-tokens", "")
	if rec2.Code != http.StatusForbidden {
		t.Errorf("operator POST /enroll-tokens: code %d, want 403", rec2.Code)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
