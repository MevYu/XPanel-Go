package dashboard

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/shirou/gopsutil/v3/host"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// panelVersion 与 cmd/xpanel 启动日志中的版本号保持一致。
const panelVersion = "0.0.1"

// Deps 注入宿主能力(取主体角色),避免反向依赖 server 包。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
}

// Module 是常驻的系统总览模块:暴露指标快照与 WS 实时推送,并存「首页软件配置」。
type Module struct {
	ds   *dashStore
	deps Deps
}

// New 建表(幂等)并返回模块。建表失败(DB 不可用)直接 panic:模块无法工作。
func New(st *store.Store, deps Deps) *Module {
	ds, err := newDashStore(st)
	if err != nil {
		panic("dashboard: init store: " + err.Error())
	}
	return &Module{ds: ds, deps: deps}
}

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

func (m *Module) Routes(r module.Router) {
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
	r.Get("/sysinfo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, sysInfo())
	})
	r.Get("/disk-partitions", func(w http.ResponseWriter, _ *http.Request) {
		parts, err := system.DiskPartitions()
		if err != nil {
			http.Error(w, "disk partitions unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, parts)
	})

	r.Get("/home-apps", m.handleGetHomeApps) // 只读:任意已认证角色
	r.Put("/home-apps", m.handlePutHomeApps) // 写:admin
}

// maxHomeApps 是首页软件配置的列表长度上限,防滥用。
const maxHomeApps = 50

type homeAppsBody struct {
	Modules []string `json:"modules"`
}

// handleGetHomeApps 返回有序的首页展示模块 id 列表;无配置返回空列表。
func (m *Module) handleGetHomeApps(w http.ResponseWriter, _ *http.Request) {
	mods, err := m.ds.getHomeApps()
	if err != nil {
		http.Error(w, "home-apps unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, homeAppsBody{Modules: mods})
}

// handlePutHomeApps 覆盖保存整个有序列表。admin only;每个 id 须为非空字符串,长度 ≤ maxHomeApps。
func (m *Module) handlePutHomeApps(w http.ResponseWriter, r *http.Request) {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var body homeAppsBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(body.Modules) > maxHomeApps {
		http.Error(w, "too many modules", http.StatusBadRequest)
		return
	}
	for _, id := range body.Modules {
		if id == "" {
			http.Error(w, "module id must be a non-empty string", http.StatusBadRequest)
			return
		}
	}
	if body.Modules == nil {
		body.Modules = []string{}
	}
	if err := m.ds.setHomeApps(body.Modules); err != nil {
		http.Error(w, "save home-apps failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, homeAppsBody{Modules: body.Modules})
}

type sysInfoResp struct {
	Hostname         string `json:"hostname"`
	OS               string `json:"os"`
	Kernel           string `json:"kernel"`
	Arch             string `json:"arch"`
	CPUModel         string `json:"cpu_model"`
	CPUPhysicalCores int    `json:"cpu_physical_cores"`
	CPULogicalCores  int    `json:"cpu_logical_cores"`
	PrivateIP        string `json:"private_ip"`
	PublicIP         string `json:"public_ip"`
	PanelVersion     string `json:"panel_version"`
	ServerTime       int64  `json:"server_time"`
}

// sysInfo 收集只读系统信息;任一来源失败仅留空对应字段,不整体报错。
func sysInfo() sysInfoResp {
	resp := sysInfoResp{PrivateIP: privateIPv4(), PanelVersion: panelVersion, ServerTime: time.Now().Unix()}
	if h, err := host.Info(); err == nil {
		resp.Hostname = h.Hostname
		resp.OS = h.Platform + " " + h.PlatformVersion
		resp.Kernel = h.KernelVersion
		resp.Arch = h.KernelArch
	}
	resp.CPUModel, resp.CPUPhysicalCores, resp.CPULogicalCores = system.CPUInfo()
	return resp
}

// privateIPv4 返回首个非回环、非链路本地的 IPv4 地址,无则返回空串。
func privateIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			return ip4.String()
		}
	}
	return ""
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
