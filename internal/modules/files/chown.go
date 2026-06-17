package files

import (
	"net/http"
	"os/user"
	"regexp"
	"strconv"
	"syscall"
)

// ownerNameRe 限定 owner/group 名为安全字符集,挡命令注入与异常输入。
var ownerNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,32}$`)

// validOwnerName 校验 owner/group 名白名单。
func validOwnerName(s string) bool { return ownerNameRe.MatchString(s) }

// lookupOwner 把 uid/gid 反查成用户名/组名;查不到回退十进制数字串。
func lookupOwner(uid, gid uint32) (owner, group string) {
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		owner = u.Username
	} else {
		owner = strconv.FormatUint(uint64(uid), 10)
	}
	if g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10)); err == nil {
		group = g.Name
	} else {
		group = strconv.FormatUint(uint64(gid), 10)
	}
	return owner, group
}

// statOwner 取路径的 owner/group 名。拿不到 Sys() 的平台返回空串。
func statOwner(sys any) (owner, group string) {
	st, ok := sys.(*syscall.Stat_t)
	if !ok {
		return "", ""
	}
	return lookupOwner(st.Uid, st.Gid)
}

type chownReq struct {
	Path      string `json:"path"`
	Owner     string `json:"owner"`
	Group     string `json:"group"`
	Recursive bool   `json:"recursive"`
}

// handleChown 改属主。owner/group 白名单 + 存在性校验,经注入的 chown 执行器(参数数组,不拼 shell)。
// 仅 admin。
func (m *Module) handleChown(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var req chownReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Owner == "" && req.Group == "" {
		http.Error(w, "owner or group required", http.StatusBadRequest)
		return
	}
	if req.Owner != "" {
		if !validOwnerName(req.Owner) {
			http.Error(w, "invalid owner name", http.StatusBadRequest)
			return
		}
		if _, err := m.lookupUser(req.Owner); err != nil {
			http.Error(w, "owner does not exist", http.StatusBadRequest)
			return
		}
	}
	if req.Group != "" {
		if !validOwnerName(req.Group) {
			http.Error(w, "invalid group name", http.StatusBadRequest)
			return
		}
		if _, err := m.lookupGroup(req.Group); err != nil {
			http.Error(w, "group does not exist", http.StatusBadRequest)
			return
		}
	}
	abs, err := m.resolve(req.Path)
	if err != nil {
		pathError(w, err)
		return
	}

	spec := req.Owner
	if req.Group != "" {
		spec += ":" + req.Group
	}
	args := []string{spec}
	if req.Recursive {
		args = []string{"-R", spec}
	}
	args = append(args, abs)
	if err := m.chown(args); err != nil {
		http.Error(w, "chown failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "files.chown", req.Path+" -> "+spec, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}
