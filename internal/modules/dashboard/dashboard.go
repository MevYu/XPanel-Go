package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Module 是常驻的系统总览模块:暴露指标快照与 WS 实时推送。
type Module struct{}

func New() *Module { return &Module{} }

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{
		ID: "dashboard", Name: "系统总览", Category: "系统", AlwaysOn: true,
	}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "系统总览", Icon: "gauge", Path: "/dashboard"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }
func (*Module) HealthCheck() error          { return nil }

func (*Module) Routes(r module.Router) {
	r.Get("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		snap, err := system.Snapshot()
		if err != nil {
			http.Error(w, "metrics unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
	})
	r.Get("/stream", streamHandler)
}

// streamHandler 每 2s 推一次指标快照,直到客户端断开。
func streamHandler(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	ctx := r.Context()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap, err := system.Snapshot()
			if err != nil {
				continue
			}
			writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = wsjson.Write(writeCtx, c, snap)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
