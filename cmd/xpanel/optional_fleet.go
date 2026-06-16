//go:build fleet

package main

import (
	"net/http"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/modules/fleet"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// optionalDeps 携带可选模块所需的宿主能力。
type optionalDeps struct {
	Principal func(*http.Request) (userID int64, role string)
	Audit     func(userID *int64, action, detail, ip string)
}

// registerOptionalModules 在 -tags fleet 时编入 fleet(集群)模块。
func registerOptionalModules(reg *module.Registry, st *store.Store, deps optionalDeps) {
	reg.Register(fleet.New(st, fleet.Deps{
		Principal: deps.Principal,
		Audit:     deps.Audit,
	}))
}
