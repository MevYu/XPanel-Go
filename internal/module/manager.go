package module

import (
	"context"
	"fmt"
	"sync"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// Manager 编排模块启用/停用:依赖校验、健康检查、Start/Stop、状态持久化与重启恢复。
type Manager struct {
	reg   *Registry
	store *store.Store

	mu      sync.RWMutex
	enabled map[string]bool
}

func NewManager(reg *Registry, st *store.Store) *Manager {
	return &Manager{reg: reg, store: st, enabled: make(map[string]bool)}
}

func (mgr *Manager) IsEnabled(id string) bool {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return mgr.enabled[id]
}

// Enable 校验依赖 → HealthCheck → Start → 持久化。任一步失败则不改变状态。
func (mgr *Manager) Enable(id string) error {
	m, ok := mgr.reg.Get(id)
	if !ok {
		return fmt.Errorf("module: unknown id %q", id)
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.enabled[id] {
		return nil
	}
	for _, dep := range m.Meta().Requires {
		if !mgr.enabled[dep] {
			return fmt.Errorf("module %q requires %q to be enabled first", id, dep)
		}
	}
	if err := m.HealthCheck(); err != nil {
		return fmt.Errorf("module %q health check failed: %w", id, err)
	}
	if err := m.Start(context.Background()); err != nil {
		return fmt.Errorf("module %q start failed: %w", id, err)
	}
	if err := mgr.store.SetModuleEnabled(id, true); err != nil {
		_ = m.Stop(context.Background()) // 回滚已启动的后台任务
		return err
	}
	mgr.enabled[id] = true
	return nil
}

// Disable 若被其他已启用模块依赖则拒绝;否则 Stop → 持久化。AlwaysOn 不可停用。
func (mgr *Manager) Disable(id string) error {
	m, ok := mgr.reg.Get(id)
	if !ok {
		return fmt.Errorf("module: unknown id %q", id)
	}
	if m.Meta().AlwaysOn {
		return fmt.Errorf("module %q is always-on and cannot be disabled", id)
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
				return fmt.Errorf("module %q is required by %q", id, other.Meta().ID)
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

// Restore 启动时调用:把 AlwaysOn 模块与上次持久化为 enabled 的模块依次启用。
func (mgr *Manager) Restore() error {
	persisted, err := mgr.store.EnabledModules()
	if err != nil {
		return err
	}
	for _, m := range mgr.reg.All() {
		id := m.Meta().ID
		if m.Meta().AlwaysOn || persisted[id] {
			if err := mgr.Enable(id); err != nil {
				return fmt.Errorf("restore %q: %w", id, err)
			}
		}
	}
	return nil
}
