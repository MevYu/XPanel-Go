package module

import (
	"context"

	"github.com/go-chi/chi/v5"
)

// 这些别名让 Module 接口不直接散落第三方类型,便于测试替身实现。
type Router = chi.Router
type Context = context.Context

// NavItem 是模块给前端的一条导航元数据。Path 是前端路由路径。
type NavItem struct {
	Label string `json:"label"`
	Icon  string `json:"icon"`
	Path  string `json:"path"`
}

// ModuleMeta 描述模块的静态元信息。
type ModuleMeta struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Requires []string `json:"requires"`
	AlwaysOn bool     `json:"always_on"`
}

// Module 是所有功能模块实现的接口。一个模块声明自己的元信息、路由、导航、生命周期与依赖自检。
type Module interface {
	Meta() ModuleMeta
	Routes(r Router)         // 挂在 /api/m/<id>/ 命名空间下
	Nav() []NavItem          // 前端导航项
	// Start/Stop/HealthCheck 必须迅速返回、不得阻塞:Manager 在持有锁期间调用它们,长时间运行的后台工作须放进 detached goroutine。
	Start(ctx Context) error // 启用时调用:起后台任务
	Stop(ctx Context) error  // 停用时调用:优雅关闭
	HealthCheck() error      // 依赖自检(如 systemctl 是否可用)
}
