package dashboard

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
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

	r.Get("/metrics/detail", func(w http.ResponseWriter, _ *http.Request) {
		d, err := system.DetailSnapshot()
		if err != nil {
			http.Error(w, "detail metrics unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, d)
	})
	r.Get("/processes", func(w http.ResponseWriter, req *http.Request) {
		limit := 20
		if v := req.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		procs, err := system.TopProcesses(limit)
		if err != nil {
			http.Error(w, "processes unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, procs)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// streamHandler 每 2s 推一次指标快照,直到客户端断开。
func streamHandler(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	// CloseRead 起一个读 goroutine 处理 close/ping/pong 控制帧,
	// 并在客户端断开时 cancel 返回的 ctx —— 使下面的 select 能即时响应断开。
	ctx := c.CloseRead(r.Context())
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap, err := system.Snapshot()
			if err != nil {
				log.Printf("dashboard stream: metrics snapshot failed: %v", err)
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
