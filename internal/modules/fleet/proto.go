//go:build fleet

package fleet

// NATS subjects(wire-format,controller 与 agent 必须一致):
//
//	fleet.enroll              — agent → controller request,换取连接凭证(此处仅注册)
//	fleet.hb                  — agent → controller publish,心跳
//	fleet.cmd.<nodeID>        — controller → agent request,定向下发命令
//
// 心跳与 enroll 用固定主题 + payload 带 node id;命令用 per-node 主题做扇出 request-reply。
const (
	subjEnroll    = "fleet.enroll"
	subjHeartbeat = "fleet.hb"
	subjCmdPrefix = "fleet.cmd." // + nodeID
)

func cmdSubject(nodeID string) string { return subjCmdPrefix + nodeID }

// enrollMsg 是 agent 入网请求:持一次性 token + 自报元信息。
type enrollMsg struct {
	Token   string `json:"token"`
	NodeID  string `json:"node_id"`
	Name    string `json:"name"`
	Tags    string `json:"tags"`
	Version string `json:"version"`
}

// enrollReply 是 controller 对入网的应答。
type enrollReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
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
