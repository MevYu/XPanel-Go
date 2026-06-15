package module

import "fmt"

// Registry 持有所有编译期注册的模块。非并发安全:仅在 init/启动期写入。
type Registry struct {
	modules map[string]Module
	order   []string // 保持注册顺序,便于稳定的 All() 输出
}

func NewRegistry() *Registry {
	return &Registry{modules: make(map[string]Module)}
}

// Register 注册一个模块;id 重复直接 panic(编译期/启动期错误,应尽早暴露)。
func (r *Registry) Register(m Module) {
	id := m.Meta().ID
	if _, exists := r.modules[id]; exists {
		panic(fmt.Sprintf("module: duplicate id %q", id))
	}
	r.modules[id] = m
	r.order = append(r.order, id)
}

func (r *Registry) Get(id string) (Module, bool) {
	m, ok := r.modules[id]
	return m, ok
}

// All 按注册顺序返回所有模块。
func (r *Registry) All() []Module {
	out := make([]Module, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.modules[id])
	}
	return out
}
