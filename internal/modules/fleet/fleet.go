//go:build fleet

// controller 模块实现:内嵌 NATS 纳管 agent,批量命令扇出 + 每节点成败聚合。
package fleet

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// 命令扇出超时上限:防 admin 设过大值拖住 controller。
const maxTimeoutSec = 600

// 扇出并发上限:防大舰队一次 job 打满 NATS 连接/文件描述符。
const fanOutConcurrency = 64

// Deps 注入宿主能力,与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string)
	Audit     func(userID *int64, action, detail, ip string)
}

// Module 是可开关的 fleet(集群)管理模块。
type Module struct {
	ss   *fleetStore
	ctl  *controller
	deps Deps
}

// New 建表(幂等)并返回模块。建表失败直接 panic:模块无法工作。
func New(st *store.Store, deps Deps) *Module {
	ss, err := newFleetStore(st)
	if err != nil {
		panic("fleet: init store: " + err.Error())
	}
	secret, err := ss.getOrCreateSecret(randToken)
	if err != nil {
		panic("fleet: init secret: " + err.Error())
	}
	return &Module{ss: ss, ctl: newController(ss, secret), deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "fleet", Name: "集群", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "集群", Icon: "network", Path: "/fleet"}}
}

// Start 起内嵌 NATS + 订阅,快速返回(controller.start 内部循环在 goroutine)。
func (m *Module) Start(context.Context) error { return m.ctl.start() }

// Stop 干净关闭 NATS 与订阅。
func (m *Module) Stop(context.Context) error { m.ctl.stop(); return nil }

// HealthCheck:fleet 无外部依赖,始终可用。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	r.Post("/enroll-tokens", m.handleCreateEnrollToken) // admin
	r.Get("/nodes", m.handleListNodes)                  // operator+
	r.Post("/nodes/{id}/approve", m.handleApproveNode)  // admin
	r.Delete("/nodes/{id}", m.handleDeleteNode)         // admin
	r.Post("/jobs", m.handleCreateJob)                  // admin
	r.Get("/jobs/{id}", m.handleGetJob)                 // operator+
}

// --- enroll ---

type enrollTokenResp struct {
	// Token 是给 agent CLI 的不透明凭证:`<enroll>.<natsSecret>`。
	// 一次性 enroll 部分入网即失效;natsSecret 部分用于 NATS 连接鉴权。
	Token string `json:"token"`
}

func (m *Module) handleCreateEnrollToken(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	enroll := randToken()
	if err := m.ss.createEnrollToken(enroll); err != nil {
		log.Printf("fleet: create enroll token: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	secret, err := m.ss.getOrCreateSecret(randToken)
	if err != nil {
		log.Printf("fleet: get secret: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "fleet.enroll_token", "created", clientIP(r))
	writeJSON(w, http.StatusCreated, enrollTokenResp{Token: enroll + "." + secret})
}

// --- nodes ---

func (m *Module) handleListNodes(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	nodes, err := m.ss.listNodes()
	if err != nil {
		log.Printf("fleet: list nodes: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (m *Module) handleApproveNode(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id := chi.URLParamFromCtx(r.Context(), "id")
	if !validNodeID(id) {
		http.Error(w, "invalid node id", http.StatusBadRequest)
		return
	}
	if err := m.ctl.approveNode(id); err != nil {
		log.Printf("fleet: approve node: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "fleet.node.approve", id, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id := chi.URLParamFromCtx(r.Context(), "id")
	if !validNodeID(id) {
		http.Error(w, "invalid node id", http.StatusBadRequest)
		return
	}
	if err := m.ctl.deleteNode(id); err != nil {
		log.Printf("fleet: delete node: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "fleet.node.delete", id, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// --- jobs ---

type createJobReq struct {
	Argv       []string `json:"argv"`     // 参数数组,绝不拼 shell
	Selector   string   `json:"selector"` // all | tag:<t> | ids:<id,id>
	TimeoutSec int      `json:"timeout_sec"`
}

type jobResp struct {
	JobID   int64       `json:"job_id"`
	Results []JobResult `json:"results"`
	Summary jobSummary  `json:"summary"`
}

type jobSummary struct {
	Total   int `json:"total"`
	Success int `json:"success"`
	Failed  int `json:"failed"`
	Timeout int `json:"timeout"`
}

func (m *Module) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req createJobReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		http.Error(w, "argv must be a non-empty command array", http.StatusBadRequest)
		return
	}
	if !validSelector(req.Selector) {
		http.Error(w, "selector must be all | tag:<t> | ids:<id,...>", http.StatusBadRequest)
		return
	}
	timeoutSec := req.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	if timeoutSec > maxTimeoutSec {
		timeoutSec = maxTimeoutSec
	}

	targets, err := m.ss.activeTargets(req.Selector)
	if err != nil {
		log.Printf("fleet: resolve targets: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	argvJSON, _ := json.Marshal(req.Argv)
	jobID, err := m.ss.createJob(Job{
		Argv: string(argvJSON), Selector: req.Selector, TimeoutSec: timeoutSec, CreatedBy: &uid,
	})
	if err != nil {
		log.Printf("fleet: create job: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, id := range targets {
		if err := m.ss.initResult(jobID, id); err != nil {
			log.Printf("fleet: init result: %v", err)
		}
	}
	m.deps.Audit(&uid, "fleet.job.create",
		strconv.FormatInt(jobID, 10)+" "+req.Selector+" "+strings.Join(req.Argv, " "), clientIP(r))

	m.fanOut(jobID, req.Argv, timeoutSec, targets)

	results, _ := m.ss.listResults(jobID)
	writeJSON(w, http.StatusOK, jobResp{JobID: jobID, Results: results, Summary: summarize(results)})
}

// fanOut 并发向各目标节点下发命令,收齐后把未回复者标 timeout。同步阻塞至全部结束或超时。
func (m *Module) fanOut(jobID int64, argv []string, timeoutSec int, targets []string) {
	timeout := time.Duration(timeoutSec) * time.Second
	done := make(chan struct{}, len(targets))
	sem := make(chan struct{}, fanOutConcurrency)
	for _, nodeID := range targets {
		go func(nodeID string) {
			sem <- struct{}{}
			defer func() { <-sem; done <- struct{}{} }()
			rep, ok := m.ctl.dispatch(nodeID, cmdMsg{JobID: jobID, Argv: argv, TimeoutSec: timeoutSec}, timeout)
			if !ok {
				return // 未回复:留作 pending,稍后统一标 timeout
			}
			status := resultSuccess
			if rep.Failed || rep.ExitCode != 0 {
				status = resultFailed
			}
			if err := m.ss.setResult(JobResult{
				JobID: jobID, NodeID: nodeID, Status: status,
				ExitCode: rep.ExitCode, Output: rep.Output, DurationMs: rep.DurationMs,
			}); err != nil {
				log.Printf("fleet: set result: %v", err)
			}
		}(nodeID)
	}
	for range targets {
		<-done
	}
	if err := m.ss.markPendingAsTimeout(jobID); err != nil {
		log.Printf("fleet: mark timeout: %v", err)
	}
}

func (m *Module) handleGetJob(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	id, err := strconv.ParseInt(chi.URLParamFromCtx(r.Context(), "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid job id", http.StatusBadRequest)
		return
	}
	if _, err := m.ss.getJob(id); err != nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	results, err := m.ss.listResults(id)
	if err != nil {
		log.Printf("fleet: list results: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, jobResp{JobID: id, Results: results, Summary: summarize(results)})
}

func summarize(results []JobResult) jobSummary {
	s := jobSummary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case resultSuccess:
			s.Success++
		case resultFailed:
			s.Failed++
		case resultTimeout:
			s.Timeout++
		}
	}
	return s
}

// --- RBAC / 校验辅助 ---

func (m *Module) requireReader(w http.ResponseWriter, r *http.Request) bool {
	_, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return false
	}
	return true
}

func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// 节点 ID 白名单:字母数字 . _ -(machine-id 或 hex),长度受限。
func validNodeID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validSelector(s string) bool {
	switch {
	case s == "all":
		return true
	case strings.HasPrefix(s, "tag:"):
		return strings.TrimPrefix(s, "tag:") != ""
	case strings.HasPrefix(s, "ids:"):
		return strings.TrimPrefix(s, "ids:") != ""
	}
	return false
}

func randToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("fleet: rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
