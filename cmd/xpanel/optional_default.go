//go:build !fleet

package main

import (
	"net/http"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// optionalDeps 携带可选模块所需的宿主能力。默认构建下未使用。
type optionalDeps struct {
	Principal func(*http.Request) (userID int64, role string)
	Audit     func(userID *int64, action, detail, ip string)
}

// registerOptionalModules 默认构建不含任何 build-tag 门控的可选模块。
func registerOptionalModules(_ *module.Registry, _ *store.Store, _ optionalDeps) {}
