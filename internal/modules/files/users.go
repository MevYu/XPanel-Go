package files

import (
	"net/http"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
)

// loginShells 是被视作可登录用户的 shell 集合;有登录 shell 的用户可作文件属主候选。
var loginShells = map[string]bool{
	"/bin/bash":     true,
	"/bin/sh":       true,
	"/bin/zsh":      true,
	"/usr/bin/bash": true,
	"/usr/bin/zsh":  true,
	"/usr/bin/fish": true,
}

// webUsers 是常见 Web 服务账号,即便 uid 低、shell 非登录也作属主候选。
var webUsers = map[string]bool{
	"www":      true,
	"www-data": true,
	"nginx":    true,
	"apache":   true,
	"apache2":  true,
	"caddy":    true,
	"http":     true,
}

type sysUser struct {
	Name  string `json:"name"`
	Group string `json:"group"`
}

// handleListUsers 列出可作文件属主的系统用户(供前端属主下拉)。仅 admin。
func (m *Module) handleListUsers(w http.ResponseWriter, r *http.Request) {
	_, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	users, err := listSystemUsers()
	if err != nil {
		http.Error(w, "read users failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// listSystemUsers 解析 /etc/passwd,挑出可作文件属主的账号,按 name 升序去重。
func listSystemUsers() ([]sysUser, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	out := make([]sysUser, 0, 16)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		name := fields[0]
		if name == "nobody" || seen[name] {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid := fields[3]
		shell := fields[6]
		if !ownerCandidate(uid, shell, name) {
			continue
		}
		seen[name] = true
		out = append(out, sysUser{Name: name, Group: groupName(gid)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ownerCandidate 判定一个账号是否是可信的文件属主候选。
func ownerCandidate(uid int, shell, name string) bool {
	return uid == 0 || uid >= 1000 || loginShells[shell] || webUsers[name]
}

// groupName 把主组 gid 反查成组名;查不到回退数字串。
func groupName(gid string) string {
	if g, err := user.LookupGroupId(gid); err == nil {
		return g.Name
	}
	return gid
}
