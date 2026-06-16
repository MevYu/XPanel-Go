//go:build fleet

package fleet

// NATS subjects(wire-format,controller 与 agent 必须一致):
//
//	fleet.enroll              — agent(引导凭证)→ controller request,入网 + 审批后取专属凭证
//	fleet.hb.<nodeID>         — agent(节点凭证)→ controller publish,心跳
//	fleet.cmd.<nodeID>        — controller → agent(节点凭证)request,定向下发命令
//
// 心跳与命令都用 per-node 主题:nodeID 即鉴权身份,subject 级 ACL 保证一个节点
// 既无法订阅他人 cmd,也无法以他人身份心跳(伪造 node_id 会被 publish 权限拒)。
const (
	subjEnroll    = "fleet.enroll"
	subjHeartbeat = "fleet.hb"   // 通配订阅前缀:controller 订 fleet.hb.*
	subjCmdPrefix = "fleet.cmd." // + nodeID
	subjHBPrefix  = "fleet.hb."  // + nodeID
)

func cmdSubject(nodeID string) string { return subjCmdPrefix + nodeID }
func hbSubject(nodeID string) string  { return subjHBPrefix + nodeID }

// enrollMsg 是 agent 入网请求:持一次性 token + 自报元信息。
type enrollMsg struct {
	Token   string `json:"token"`
	NodeID  string `json:"node_id"`
	Name    string `json:"name"`
	Tags    string `json:"tags"`
	Version string `json:"version"`
}

// enrollReply 是 controller 对入网的应答。
//
// 入网分两步:首次 enroll 注册为 pending(OK=true, Approved=false, 无凭证);
// admin 审批后 agent 再次以同一(已用)token 轮询,审批通过则 Approved=true 并下发
// 专属凭证 NodeUser/NodePass,agent 用它重连。Approved=false 表示仍待审批,继续轮询。
type enrollReply struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Approved bool   `json:"approved,omitempty"`
	NodeUser string `json:"node_user,omitempty"`
	NodePass string `json:"node_pass,omitempty"`
}

// heartbeatMsg 是 agent 周期上报。
type heartbeatMsg struct {
	NodeID  string `json:"node_id"`
	Version string `json:"version"`
}

// cmdMsg 是 controller 下发的命令:参数数组(绝不拼 shell)+ 超时。
type cmdMsg struct {
	JobID      int64    `json:"job_id"`
	Argv       []string `json:"argv"`
	TimeoutSec int      `json:"timeout_sec"`
}

// cmdReply 是 agent 执行后的回传。
type cmdReply struct {
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	DurationMs int64  `json:"duration_ms"`
	Failed     bool   `json:"failed"` // 进程无法启动等非退出码失败
}
