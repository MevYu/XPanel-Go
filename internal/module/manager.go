package module

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// ValidationError 表示用户可安全展示的校验失败(未知 id / 依赖未满足 / AlwaysOn / 被依赖占用),不含内部敏感信息。
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Health 是模块依赖自检的咨询结果:OK=true 表示依赖就绪;OK=false 时 Reason 给出原因
// (如 "systemctl not found")。健康与否不影响模块能否启用,只用于前端状态提示。
type Health struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}

// Manager 编排模块启用/停用:依赖校验、Start/Stop、状态持久化与重启恢复。
// HealthCheck 仅作咨询:失败也允许启用,结果记入 health 供前端提示。
type Manager struct {
	reg   *Registry
	store *store.Store

	mu      sync.RWMutex
	enabled map[string]bool
	health  map[string]Health // 启用时记录的最近一次 HealthCheck 结果
}

func NewManager(reg *Registry, st *store.Store) *Manager {
	return &Manager{reg: reg, store: st, enabled: make(map[string]bool), health: make(map[string]Health)}
}

func (mgr *Manager) IsEnabled(id string) bool {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return mgr.enabled[id]
}

// Health 返回模块的健康状态。已启用模块返回启用时记录的结果;未记录(未启用)则现算一次
// HealthCheck(通常很快,如 LookPath)。未知 id 返回零值(OK=false, Reason="")。
func (mgr *Manager) Health(id string) Health {
	mgr.mu.RLock()
	h, recorded := mgr.health[id]
	mgr.mu.RUnlock()
	if recorded {
		return h
	}
	m, ok := mgr.reg.Get(id)
	if !ok {
		return Health{}
	}
	return checkHealth(m)
}

// checkHealth 跑模块 HealthCheck 并归一为咨询结果。
func checkHealth(m Module) Health {
	if err := m.HealthCheck(); err != nil {
		return Health{OK: false, Reason: err.Error()}
	}
	return Health{OK: true}
}

// Enable 校验依赖 → 记录 HealthCheck(咨询,不挡)→ Start → 持久化。
// 依赖未满足或 Start 失败则拒绝;HealthCheck 失败只记入 health,启用照常成功。
func (mgr *Manager) Enable(id string) error {
	m, ok := mgr.reg.Get(id)
	if !ok {
		return &ValidationError{Msg: fmt.Sprintf("module: unknown id %q", id)}
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.enabled[id] {
		return nil
	}
	for _, dep := range m.Meta().Requires {
		if !mgr.enabled[dep] {
			return &ValidationError{Msg: fmt.Sprintf("module %q requires %q to be enabled first", id, dep)}
		}
	}
	health := checkHealth(m)
	if err := m.Start(context.Background()); err != nil {
		return fmt.Errorf("module %q start failed: %w", id, err)
	}
	if err := mgr.store.SetModuleEnabled(id, true); err != nil {
		// 回滚已启动的后台任务;Stop 错误并入返回值,以便诊断"已启动但标记为停用"的状态泄漏。
		return errors.Join(err, m.Stop(context.Background()))
	}
	mgr.enabled[id] = true
	mgr.health[id] = health
	return nil
}

// Disable 若被其他已启用模块依赖则拒绝;否则 Stop → 持久化。AlwaysOn 不可停用。
func (mgr *Manager) Disable(id string) error {
	m, ok := mgr.reg.Get(id)
	if !ok {
		return &ValidationError{Msg: fmt.Sprintf("module: unknown id %q", id)}
	}
	if m.Meta().AlwaysOn {
		return &ValidationError{Msg: fmt.Sprintf("module %q is always-on and cannot be disabled", id)}
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if !mgr.enabled[id] {
		return nil
	}
	for _, other := range mgr.reg.All() {
		if !mgr.enabled[other.Meta().ID] {
			continue
		}
		for _, dep := range other.Meta().Requires {
			if dep == id {
				return &ValidationError{Msg: fmt.Sprintf("module %q is required by %q", id, other.Meta().ID)}
			}
		}
	}
	if err := m.Stop(context.Background()); err != nil {
		return fmt.Errorf("module %q stop failed: %w", id, err)
	}
	if err := mgr.store.SetModuleEnabled(id, false); err != nil {
		return err
	}
	mgr.enabled[id] = false
	return nil
}

// Restore 启动时调用:启用 AlwaysOn 与上次持久化为 enabled 的模块。
// 不依赖注册顺序——反复扫描,每轮启用依赖已满足的模块,直至无剩余或无进展。
func (mgr *Manager) Restore() error {
	persisted, err := mgr.store.EnabledModules()
	if err != nil {
		return err
	}
	want := make(map[string]bool)
	for _, m := range mgr.reg.All() {
		id := m.Meta().ID
		if m.Meta().AlwaysOn || persisted[id] {
			want[id] = true
		}
	}
	for len(want) > 0 {
		progressed := false
		for id := range want {
			m, _ := mgr.reg.Get(id)
			ready := true
			for _, dep := range m.Meta().Requires {
				if !mgr.IsEnabled(dep) {
					ready = false
					break
				}
			}
			if !ready {
				continue
			}
			if err := mgr.Enable(id); err != nil {
				return fmt.Errorf("restore %q: %w", id, err)
			}
			delete(want, id)
			progressed = true
		}
		if !progressed {
			return errors.New("restore: unsatisfiable module dependencies")
		}
	}
	return nil
}
