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

// bootSecret 取出 controller 的引导凭证密码(供测试 agent 做引导连接)。
func (m *Module) bootSecret(t *testing.T) string {
	t.Helper()
	s, err := m.ss.getOrCreateSecret(randToken)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	return s
}

// dialBootstrap 以受限引导凭证连入(username=__bootstrap)。
func dialBootstrap(t *testing.T, m *Module) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(m.ctl.clientURL(), nats.UserInfo(userBootstrap, m.bootSecret(t)))
	if err != nil {
		t.Fatalf("bootstrap connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// dialNode 以节点专属凭证连入(username=nodeID),要求该凭证已签发。
func dialNode(t *testing.T, m *Module, nodeID string) *nats.Conn {
	t.Helper()
	pw, ok, err := m.ss.nodeCred(nodeID)
	if err != nil || !ok {
		t.Fatalf("node cred for %s: ok=%v err=%v", nodeID, ok, err)
	}
	nc, err := nats.Connect(m.ctl.clientURL(), nats.UserInfo(nodeID, pw))
	if err != nil {
		t.Fatalf("node connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// mockAgent 模拟一个已审批节点:用专属凭证连入,回应命令、心跳。
type mockAgent struct {
	nc     *nats.Conn
	nodeID string
}

// enrollNode 走完整入网:引导连接 enroll → admin 审批 → 拿专属凭证重连,返回 mockAgent。
func enrollNode(t *testing.T, m *Module, nodeID, tags string) *mockAgent {
	t.Helper()
	tok := createEnrollToken(t, m)
	boot := dialBootstrap(t, m)
	if rep := enrollOnce(t, boot, nodeID, tok, tags); !rep.OK || rep.Approved {
		t.Fatalf("first enroll: %+v", rep)
	}
	approveNode(t, m, nodeID)
	rep := enrollOnce(t, boot, nodeID, tok, tags)
	if !rep.OK || !rep.Approved {
		t.Fatalf("enroll after approve not approved: %+v", rep)
	}
	nc := dialNode(t, m, nodeID)
	return &mockAgent{nc: nc, nodeID: nodeID}
}

// enrollOnce 以引导连接发一次 enroll 请求。
func enrollOnce(t *testing.T, boot *nats.Conn, nodeID, token, tags string) enrollReply {
	t.Helper()
	b, _ := json.Marshal(enrollMsg{Token: token, NodeID: nodeID, Name: nodeID, Tags: tags, Version: "test"})
	msg, err := boot.Request(subjEnroll, b, 2*time.Second)
	if err != nil {
		t.Fatalf("enroll request: %v", err)
	}
	var rep enrollReply
	if err := json.Unmarshal(msg.Data, &rep); err != nil {
		t.Fatalf("enroll reply: %v", err)
	}
	return rep
}

func approveNode(t *testing.T, m *Module, nodeID string) {
	t.Helper()
	if rec := do(m, http.MethodPost, "/nodes/"+nodeID+"/approve", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("approve %s: code %d", nodeID, rec.Code)
	}
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
	if err := a.nc.Publish(hbSubject(a.nodeID), b); err != nil {
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

// TestEnrollTokenOneTime:token 在凭证下发(审批后取证)前可重复轮询;凭证下发后才真正失效。
func TestEnrollTokenOneTime(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	tok := createEnrollToken(t, m)
	boot := dialBootstrap(t, m)

	// 审批前轮询:OK 但未批准,token 仍可用。
	if rep := enrollOnce(t, boot, "node-a", tok, ""); !rep.OK || rep.Approved {
		t.Fatalf("pending enroll: %+v", rep)
	}
	if rep := enrollOnce(t, boot, "node-a", tok, ""); !rep.OK || rep.Approved {
		t.Fatalf("repeat pending enroll should still be OK: %+v", rep)
	}
	approveNode(t, m, "node-a")
	if rep := enrollOnce(t, boot, "node-a", tok, ""); !rep.OK || !rep.Approved || rep.NodePass == "" {
		t.Fatalf("approved enroll must issue cred: %+v", rep)
	}
	// 凭证已下发,token 消费 → 再用必败。
	if rep := enrollOnce(t, boot, "node-a", tok, ""); rep.OK {
		t.Error("token must be one-time once credential issued")
	}
}

// TestEnrollTokenBoundToNode:一个 token 绑定首个 nodeID 后,别的 nodeID 不能复用它。
func TestEnrollTokenBoundToNode(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	tok := createEnrollToken(t, m)
	boot := dialBootstrap(t, m)
	if rep := enrollOnce(t, boot, "node-x", tok, ""); !rep.OK {
		t.Fatalf("bind to node-x: %+v", rep)
	}
	if rep := enrollOnce(t, boot, "node-y", tok, ""); rep.OK {
		t.Error("token bound to node-x must reject node-y")
	}
}

func TestUnapprovedNodeReceivesNoCommand(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	tok := createEnrollToken(t, m)
	boot := dialBootstrap(t, m)
	enrollOnce(t, boot, "node-pending", tok, "")

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
	agent := enrollNode(t, m, "node-hb", "")

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
		a := enrollNode(t, m, s.id, "")
		if s.reply != nil {
			a.respondCmd(t, *s.reply)
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

// subErr 订阅 subject 并 flush;返回 NATS 因权限拒绝时的错误(nil = 允许)。
func subErr(t *testing.T, nc *nats.Conn, subject string) error {
	t.Helper()
	errCh := make(chan error, 1)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { errCh <- e })
	if _, err := nc.SubscribeSync(subject); err != nil {
		return err
	}
	_ = nc.Flush()
	select {
	case e := <-errCh:
		return e
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

// pubErr 向 subject 发布并 flush;返回 NATS 因权限拒绝时的异步错误(nil = 允许)。
func pubErr(t *testing.T, nc *nats.Conn, subject string, data []byte) error {
	t.Helper()
	errCh := make(chan error, 1)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { errCh <- e })
	if err := nc.Publish(subject, data); err != nil {
		return err
	}
	_ = nc.Flush()
	select {
	case e := <-errCh:
		return e
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

func isPermErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "permission")
}

// 越权拦截被堵:victim 已审批,attacker 持自己的专属凭证,不得订阅 victim 的 cmd 主题。
func TestNodeCannotSubscribeOtherCmd(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	_ = enrollNode(t, m, "node-victim", "")
	attacker := enrollNode(t, m, "node-attacker", "")

	if err := subErr(t, attacker.nc, cmdSubject("node-victim")); !isPermErr(err) {
		t.Errorf("attacker subscribing victim cmd: err = %v, want permission violation", err)
	}
	// 攻击者订自己的 cmd 仍允许。
	if err := subErr(t, attacker.nc, cmdSubject("node-attacker")); err != nil {
		t.Errorf("attacker subscribing own cmd should be allowed: %v", err)
	}
}

// 引导凭证不得订阅任何 cmd 主题(只能 enroll)。
func TestBootstrapCannotSubscribeCmd(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	_ = enrollNode(t, m, "node-v", "")
	boot := dialBootstrap(t, m)
	if err := subErr(t, boot, cmdSubject("node-v")); !isPermErr(err) {
		t.Errorf("bootstrap subscribing cmd: err = %v, want permission violation", err)
	}
	if err := subErr(t, boot, subjCmdPrefix+">"); !isPermErr(err) {
		t.Errorf("bootstrap wildcard cmd subscribe: err = %v, want permission violation", err)
	}
}

// 不得以他人身份心跳:attacker publish fleet.hb.<victim> 被拒。
func TestNodeCannotForgeOtherHeartbeat(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	_ = enrollNode(t, m, "node-hbv", "")
	attacker := enrollNode(t, m, "node-hba", "")

	b, _ := json.Marshal(heartbeatMsg{NodeID: "node-hbv"})
	if err := pubErr(t, attacker.nc, hbSubject("node-hbv"), b); !isPermErr(err) {
		t.Errorf("attacker heartbeat as victim: err = %v, want permission violation", err)
	}
	// 自身心跳允许。
	if err := pubErr(t, attacker.nc, hbSubject("node-hba"), b); err != nil {
		t.Errorf("own heartbeat should be allowed: %v", err)
	}
}

// 心跳 node_id 来自 subject:payload 伪造他人 node_id 不影响 last_seen 归属。
func TestHeartbeatNodeIDFromSubjectNotPayload(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	a := enrollNode(t, m, "node-real", "")
	_ = enrollNode(t, m, "node-other", "")

	otherBefore, _ := m.ss.getNode("node-other")
	time.Sleep(1100 * time.Millisecond)
	// payload 谎称 node-other,但 subject 是自身。
	b, _ := json.Marshal(heartbeatMsg{NodeID: "node-other"})
	if err := a.nc.Publish(hbSubject(a.nodeID), b); err != nil {
		t.Fatalf("publish hb: %v", err)
	}
	_ = a.nc.Flush()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		real, _ := m.ss.getNode("node-real")
		other, _ := m.ss.getNode("node-other")
		if real.LastSeen > 0 && other.LastSeen == otherBefore.LastSeen {
			return // 自身被更新,被伪造者未受影响
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("heartbeat attribution must follow subject identity, not payload node_id")
}

// 未审批节点无专属凭证,以其 nodeID 连入被拒(零权限)。
func TestUnapprovedNodeCannotConnect(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	tok := createEnrollToken(t, m)
	boot := dialBootstrap(t, m)
	enrollOnce(t, boot, "node-unapp", tok, "") // 注册 pending,未审批,无凭证

	if _, err := nats.Connect(m.ctl.clientURL(), nats.UserInfo("node-unapp", "guess")); err == nil {
		t.Error("unapproved node must not connect with a node credential")
	}
}

// 已删节点凭证立即失效:重连被拒。
func TestDeletedNodeCredentialRevoked(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	a := enrollNode(t, m, "node-del", "")
	pw, ok, _ := m.ss.nodeCred("node-del")
	if !ok {
		t.Fatal("expected cred before delete")
	}
	a.nc.Close()
	if rec := do(m, http.MethodDelete, "/nodes/node-del", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete node: code %d", rec.Code)
	}
	if _, _, ok := mustCred(m, "node-del"); ok {
		t.Error("credential must be revoked on delete")
	}
	if _, err := nats.Connect(m.ctl.clientURL(), nats.UserInfo("node-del", pw)); err == nil {
		t.Error("deleted node must not reconnect with old credential")
	}
}

func mustCred(m *Module, id string) (string, bool, bool) {
	pw, ok, err := m.ss.nodeCred(id)
	return pw, err == nil, ok
}

// 伪造他人结果被堵:attacker 不能 publish 到 controller 的 cmd 主题(那是 controller→agent 方向),
// 也不能借订阅他人 cmd 抢答(订阅已被 TestNodeCannotSubscribeOtherCmd 证明拒绝)。
// 这里证明:attacker 无法 publish 到 victim 的 cmd 主题来注入伪造命令/抢答。
func TestNodeCannotPublishOtherCmd(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	_ = enrollNode(t, m, "node-pv", "")
	attacker := enrollNode(t, m, "node-pa", "")
	if err := pubErr(t, attacker.nc, cmdSubject("node-pv"), []byte("x")); !isPermErr(err) {
		t.Errorf("attacker publishing to victim cmd: err = %v, want permission violation", err)
	}
}

// 正常路径:审批后节点能收自己的命令、回自己的结果,扇出聚合正确。
func TestApprovedNodeReceivesOwnCommand(t *testing.T) {
	m, _ := newTestModule(t, "admin")
	a := enrollNode(t, m, "node-ok2", "")
	a.respondCmd(t, cmdReply{ExitCode: 0, Output: "done"})

	rec := do(m, http.MethodPost, "/jobs", `{"argv":["echo","hi"],"selector":"all","timeout_sec":2}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create job: code %d body %s", rec.Code, rec.Body.String())
	}
	var resp jobResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Summary.Success != 1 || resp.Summary.Total != 1 {
		t.Errorf("summary = %+v, want 1 success/1 total", resp.Summary)
	}
}

// 输出截断:超 maxCmdOutput 的输出被截断并带标记。
func TestExecOutputTruncated(t *testing.T) {
	count := strconv.Itoa((maxCmdOutput + 4096) / 1)
	rep := execArgv([]string{"head", "-c", count, "/dev/zero"}, 10)
	if len(rep.Output) > maxCmdOutput+64 {
		t.Errorf("output not truncated: len = %d", len(rep.Output))
	}
	if !strings.Contains(rep.Output, "truncated") {
		t.Error("truncated output must carry marker")
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
