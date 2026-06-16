// Package docker 实现容器/镜像/Compose 管理模块:经 docker CLI(参数数组,绝不拼 shell)
// 列出与操作容器、镜像、网络、卷与 compose 项目。资源名/ID/项目名严格白名单,
// 危险操作(remove/down)需 admin + X-Confirm-Danger + 审计。compose 目录等路径可配置并持久化。
package docker

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// 每次 docker 调用的超时上限。pull 可能较慢,故给较宽裕值。
const cmdTimeout = 120 * time.Second

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的 docker 管理模块。
type Module struct {
	ss   *dockStore
	run  Runner
	deps Deps
}

// New 建表并返回模块。建表失败(如 DB 不可用)直接 panic:模块无法工作。
func New(st *store.Store, run Runner, deps Deps) *Module {
	ss, err := newDockStore(st)
	if err != nil {
		panic("docker: init store: " + err.Error())
	}
	return &Module{ss: ss, run: run, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "docker", Name: "容器", Category: "应用"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "容器", Icon: "box", Path: "/docker"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:docker daemon 连不上则不允许启用。
func (m *Module) HealthCheck() error { return m.run.Available() }

func (m *Module) Routes(r module.Router) {
	// 容器
	r.Get("/containers", m.handleContainerList)        // 只读 operator+
	r.Get("/containers/stats", m.handleContainerStats) // 只读:CPU/内存占用
	r.Get("/containers/{ref}/inspect", m.handleContainerInspect)
	r.Get("/containers/{ref}/logs", m.handleContainerLogs)
	r.Post("/containers/{ref}/{verb:start|stop|restart|pause|unpause}", m.handleContainerAction) // 写
	r.Post("/containers/{ref}/rename", m.handleContainerRename)                                  // 写
	r.Post("/containers/{ref}/exec", m.handleContainerExec)                                      // 写
	r.Post("/containers/{ref}/update", m.handleContainerUpdate)                                  // 危险:改资源限制
	r.Delete("/containers/{ref}", m.handleContainerRemove)                                       // 危险

	// 镜像
	r.Get("/images", m.handleImageList) // 只读
	r.Get("/images/{ref}/history", m.handleImageHistory)
	r.Post("/images/pull", m.handleImagePull)
	r.Post("/images/{ref}/tag", m.handleImageTag)
	r.Post("/images/prune", m.handleImagePrune)    // 危险
	r.Delete("/images/{ref}", m.handleImageRemove) // 危险

	// compose
	r.Get("/compose", m.handleComposeList) // 只读
	r.Get("/compose/{project}/config", m.handleComposeConfig)
	r.Get("/compose/{project}/logs", m.handleComposeLogs)
	r.Post("/compose/{project}/up", m.handleComposeUp)
	r.Post("/compose/{project}/restart", m.handleComposeRestart)
	r.Post("/compose/{project}/down", m.handleComposeDown) // 危险

	// 网络
	r.Get("/networks", m.handleNetworkList) // 只读
	r.Get("/networks/{ref}/inspect", m.handleNetworkInspect)
	r.Post("/networks", m.handleNetworkCreate)
	r.Delete("/networks/{ref}", m.handleNetworkRemove) // 危险

	// 卷
	r.Get("/volumes", m.handleVolumeList) // 只读
	r.Get("/volumes/{ref}/inspect", m.handleVolumeInspect)
	r.Post("/volumes", m.handleVolumeCreate)
	r.Delete("/volumes/{ref}", m.handleVolumeRemove) // 危险

	// 镜像仓库(凭证加密)
	r.Get("/registries", m.handleRegistryList)             // admin
	r.Post("/registries", m.handleRegistryLogin)           // admin:登录并加密落库
	r.Delete("/registries/{name}", m.handleRegistryRemove) // admin

	// 设置
	r.Get("/settings", m.handleGetSettings) // admin
	r.Put("/settings", m.handlePutSettings) // admin
}

// --- 容器 ---

func (m *Module) handleContainerList(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	m.runJSONLines(w, r, "container.list", "ps", "-a", "--no-trunc", "--format", "{{json .}}")
}

func (m *Module) handleContainerInspect(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	m.runPassthrough(w, r, "inspect", ref)
}

func (m *Module) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	tail := clampTail(r.URL.Query().Get("tail"))
	m.runPassthrough(w, r, "logs", "--tail", tail, ref)
}

func (m *Module) handleContainerAction(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	m.runAction(w, r, uid, "container."+verb, ref, verb, ref)
}

// handleContainerRemove 删除容器:危险,需 admin + 确认。-f 强制删除运行中的容器。
func (m *Module) handleContainerRemove(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	m.runAction(w, r, uid, "container.remove", ref, "rm", "-f", ref)
}

// handleContainerStats 返回所有容器的 CPU/内存占用快照(--no-trunc 不支持,故不传)。
func (m *Module) handleContainerStats(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	m.runJSONLines(w, r, "container.stats", "stats", "--no-stream", "--format", "{{json .}}")
}

type renameRequest struct {
	Name string `json:"name"`
}

// handleContainerRename 重命名容器:写操作。
func (m *Module) handleContainerRename(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	var req renameRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if !validName(req.Name) {
		http.Error(w, "invalid new container name", http.StatusBadRequest)
		return
	}
	m.runAction(w, r, uid, "container.rename", ref+"->"+req.Name, "rename", ref, req.Name)
}

type execRequest struct {
	Cmd []string `json:"cmd"`
}

// handleContainerExec 在容器内执行命令(无 TTY,非交互),返回合并输出。
// 命令以参数数组传给 docker exec,不进 shell。为后续 web 终端预留:走 exec 即可。
func (m *Module) handleContainerExec(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	var req execRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if len(req.Cmd) == 0 || len(req.Cmd) > 64 {
		http.Error(w, "cmd must be a non-empty array (<=64 args)", http.StatusBadRequest)
		return
	}
	for _, a := range req.Cmd {
		if !validExecArg(a) {
			http.Error(w, "invalid exec argument", http.StatusBadRequest)
			return
		}
	}
	args := append([]string{"exec", ref}, req.Cmd...)
	m.runAction(w, r, uid, "container.exec", ref+" "+strings.Join(req.Cmd, " "), args...)
}

type updateRequest struct {
	Memory string `json:"memory"` // docker --memory 语法,如 "512m";空=不改
	CPUs   string `json:"cpus"`   // docker --cpus,如 "1.5";空=不改
}

// handleContainerUpdate 调整容器资源限制(--memory/--cpus):危险,需 admin + 确认。
func (m *Module) handleContainerUpdate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	var req updateRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if !validMemory(req.Memory) || !validCPUs(req.CPUs) {
		http.Error(w, "invalid memory or cpus value", http.StatusBadRequest)
		return
	}
	if req.Memory == "" && req.CPUs == "" {
		http.Error(w, "at least one of memory/cpus required", http.StatusBadRequest)
		return
	}
	args := []string{"update"}
	if req.Memory != "" {
		args = append(args, "--memory", req.Memory)
	}
	if req.CPUs != "" {
		args = append(args, "--cpus", req.CPUs)
	}
	args = append(args, ref)
	m.runAction(w, r, uid, "container.update", ref+" mem="+req.Memory+" cpus="+req.CPUs, args...)
}

// --- 镜像 ---

func (m *Module) handleImageList(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	m.runJSONLines(w, r, "image.list", "images", "--no-trunc", "--format", "{{json .}}")
}

type pullRequest struct {
	Image string `json:"image"`
}

func (m *Module) handleImagePull(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req pullRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !ValidRef(req.Image) {
		http.Error(w, "invalid image ref", http.StatusBadRequest)
		return
	}
	m.runAction(w, r, uid, "image.pull", req.Image, "pull", req.Image)
}

// handleImageRemove 删除镜像:危险,需 admin + 确认。
func (m *Module) handleImageRemove(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	m.runAction(w, r, uid, "image.remove", ref, "rmi", ref)
}

// handleImageHistory 返回镜像分层历史。
func (m *Module) handleImageHistory(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	m.runJSONLines(w, r, "image.history", "history", "--no-trunc", "--format", "{{json .}}", ref)
}

type tagRequest struct {
	Target string `json:"target"`
}

// handleImageTag 给镜像打新 tag:写操作。
func (m *Module) handleImageTag(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	var req tagRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if !ValidRef(req.Target) {
		http.Error(w, "invalid target tag", http.StatusBadRequest)
		return
	}
	m.runAction(w, r, uid, "image.tag", ref+"->"+req.Target, "tag", ref, req.Target)
}

// handleImagePrune 清理悬空镜像:危险,需 admin + 确认。
func (m *Module) handleImagePrune(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	m.runAction(w, r, uid, "image.prune", "dangling", "image", "prune", "-f")
}

// --- compose ---

func (m *Module) handleComposeList(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	m.runJSONLines(w, r, "compose.list", "compose", "ls", "-a", "--format", "json")
}

func (m *Module) handleComposeUp(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	dir, project, ok := m.composeDir(w, r)
	if !ok {
		return
	}
	m.runAction(w, r, uid, "compose.up", project,
		"compose", "--project-directory", dir, "-p", project, "up", "-d")
}

// handleComposeDown 停止并移除 compose 项目:危险,需 admin + 确认。
func (m *Module) handleComposeDown(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	dir, project, ok := m.composeDir(w, r)
	if !ok {
		return
	}
	m.runAction(w, r, uid, "compose.down", project,
		"compose", "--project-directory", dir, "-p", project, "down")
}

// handleComposeConfig 输出解析后的 compose 配置(只读)。
func (m *Module) handleComposeConfig(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	dir, project, ok := m.composeDir(w, r)
	if !ok {
		return
	}
	m.runPassthrough(w, r, "compose", "--project-directory", dir, "-p", project, "config")
}

// handleComposeLogs 返回 compose 项目日志(只读,--no-color 取末尾若干行)。
func (m *Module) handleComposeLogs(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	dir, project, ok := m.composeDir(w, r)
	if !ok {
		return
	}
	tail := clampTail(r.URL.Query().Get("tail"))
	m.runPassthrough(w, r, "compose", "--project-directory", dir, "-p", project,
		"logs", "--no-color", "--tail", tail)
}

// handleComposeRestart 重启 compose 项目服务:写操作。
func (m *Module) handleComposeRestart(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	dir, project, ok := m.composeDir(w, r)
	if !ok {
		return
	}
	m.runAction(w, r, uid, "compose.restart", project,
		"compose", "--project-directory", dir, "-p", project, "restart")
}

// --- 网络 ---

func (m *Module) handleNetworkList(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	m.runJSONLines(w, r, "network.list", "network", "ls", "--no-trunc", "--format", "{{json .}}")
}

func (m *Module) handleNetworkInspect(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	m.runPassthrough(w, r, "network", "inspect", ref)
}

type createNameRequest struct {
	Name string `json:"name"`
}

// handleNetworkCreate 创建网络:写操作。
func (m *Module) handleNetworkCreate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req createNameRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if !validName(req.Name) {
		http.Error(w, "invalid network name", http.StatusBadRequest)
		return
	}
	m.runAction(w, r, uid, "network.create", req.Name, "network", "create", req.Name)
}

// handleNetworkRemove 删除网络:危险,需 admin + 确认。
func (m *Module) handleNetworkRemove(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	m.runAction(w, r, uid, "network.remove", ref, "network", "rm", ref)
}

// --- 卷 ---

func (m *Module) handleVolumeList(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	m.runJSONLines(w, r, "volume.list", "volume", "ls", "--format", "{{json .}}")
}

func (m *Module) handleVolumeInspect(w http.ResponseWriter, r *http.Request) {
	if !m.requireReader(w, r) {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	m.runPassthrough(w, r, "volume", "inspect", ref)
}

// handleVolumeCreate 创建卷:写操作。
func (m *Module) handleVolumeCreate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req createNameRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if !validName(req.Name) {
		http.Error(w, "invalid volume name", http.StatusBadRequest)
		return
	}
	m.runAction(w, r, uid, "volume.create", req.Name, "volume", "create", req.Name)
}

// handleVolumeRemove 删除卷:危险,需 admin + 确认。
func (m *Module) handleVolumeRemove(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	ref, ok := m.refParam(w, r)
	if !ok {
		return
	}
	m.runAction(w, r, uid, "volume.remove", ref, "volume", "rm", ref)
}

// --- 镜像仓库 ---

func (m *Module) handleRegistryList(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	regs, err := m.ss.listRegistries()
	if err != nil {
		log.Printf("docker: list registries failed: %v", err)
		http.Error(w, "registries unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, regs)
}

type registryLoginRequest struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleRegistryLogin 登录镜像仓库并加密落库凭证:admin。
// 密码经 stdin 传给 docker login --password-stdin,绝不进参数/进程列表/日志。
func (m *Module) handleRegistryLogin(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req registryLoginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if !validName(req.Name) || !validServer(req.Server) || req.Username == "" || req.Password == "" {
		http.Error(w, "invalid registry name/server/username/password", http.StatusBadRequest)
		return
	}
	if !validExecArg(req.Username) || !validExecArg(req.Password) {
		http.Error(w, "invalid username or password", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), cmdTimeout)
	defer cancel()
	_, err := m.run.RunInput(ctx, req.Password,
		"login", req.Server, "--username", req.Username, "--password-stdin")
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "docker.registry.login", req.Name+" "+req.Server+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("docker: registry login %q failed: %v", req.Name, err)
		http.Error(w, "registry login failed", http.StatusBadGateway)
		return
	}

	cryp, err := m.cryptor()
	if err != nil {
		log.Printf("docker: cryptor init failed: %v", err)
		http.Error(w, "registry store failed", http.StatusInternalServerError)
		return
	}
	enc, err := cryp.encrypt(req.Password)
	if err != nil {
		log.Printf("docker: encrypt registry password failed: %v", err)
		http.Error(w, "registry store failed", http.StatusInternalServerError)
		return
	}
	reg := Registry{Name: req.Name, Server: req.Server, Username: req.Username, CreatedAt: time.Now().Unix()}
	if err := m.ss.saveRegistry(reg, enc); err != nil {
		log.Printf("docker: save registry failed: %v", err)
		http.Error(w, "registry store failed", http.StatusInternalServerError)
		return
	}
	reg.Password = ""
	writeJSON(w, http.StatusOK, reg)
}

// handleRegistryRemove 删除仓库凭证记录:admin。不调用 docker logout(不影响其它凭证)。
func (m *Module) handleRegistryRemove(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	name := chi.URLParamFromCtx(r.Context(), "name")
	if !validName(name) {
		http.Error(w, "invalid registry name", http.StatusBadRequest)
		return
	}
	existed, err := m.ss.deleteRegistry(name)
	if err != nil {
		log.Printf("docker: delete registry failed: %v", err)
		http.Error(w, "registry delete failed", http.StatusInternalServerError)
		return
	}
	if !existed {
		http.Error(w, "registry not found", http.StatusNotFound)
		return
	}
	m.deps.Audit(&uid, "docker.registry.remove", name, m.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

// --- 设置 ---

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	set, err := m.ss.loadSettings()
	if err != nil {
		log.Printf("docker: load settings failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var set Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&set); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validDir(set.ComposeDir) || !validDir(set.DockerRoot) {
		http.Error(w, "compose_dir and docker_root must be absolute paths without control chars", http.StatusBadRequest)
		return
	}
	if err := m.ss.saveSettings(set); err != nil {
		log.Printf("docker: save settings failed: %v", err)
		http.Error(w, "save settings failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "docker.settings", set.ComposeDir+" "+set.DockerRoot, m.clientIP(r))
	writeJSON(w, http.StatusOK, set)
}

// --- 执行辅助 ---

// runJSONLines 执行只读 docker 命令,把每行 JSON 解析为对象数组返回。
// docker `--format '{{json .}}'` 逐行输出对象;`compose ls --format json` 直接输出数组。
func (m *Module) runJSONLines(w http.ResponseWriter, r *http.Request, action string, args ...string) {
	ctx, cancel := context.WithTimeout(r.Context(), cmdTimeout)
	defer cancel()
	out, err := m.run.Run(ctx, args...)
	if err != nil {
		log.Printf("docker: %s failed: %v", action, err)
		http.Error(w, "docker command failed", http.StatusBadGateway)
		return
	}
	items, err := parseJSONLines(out)
	if err != nil {
		log.Printf("docker: %s parse failed: %v", action, err)
		http.Error(w, "docker output parse failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// runPassthrough 执行只读 docker 命令,原样返回文本输出(inspect/logs)。
func (m *Module) runPassthrough(w http.ResponseWriter, r *http.Request, args ...string) {
	ctx, cancel := context.WithTimeout(r.Context(), cmdTimeout)
	defer cancel()
	out, err := m.run.Run(ctx, args...)
	if err != nil {
		log.Printf("docker: %s failed: %v", strings.Join(args, " "), err)
		http.Error(w, "docker command failed", http.StatusBadGateway)
		return
	}
	writePlain(w, out)
}

// runAction 执行写/危险 docker 命令并审计。detail 为审计描述(资源名)。
func (m *Module) runAction(w http.ResponseWriter, r *http.Request, uid int64, action, detail string, args ...string) {
	ctx, cancel := context.WithTimeout(r.Context(), cmdTimeout)
	defer cancel()
	out, err := m.run.Run(ctx, args...)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "docker."+action, detail+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("docker: %s %q failed: %v", action, detail, err)
		http.Error(w, "docker command failed", http.StatusBadGateway)
		return
	}
	writePlain(w, out)
}

// parseJSONLines 解析 docker 输出:若整体是 JSON 数组直接用;否则按行解析每行一个对象。
// 空输出返回空数组(避免前端拿到 null)。
func parseJSONLines(out string) ([]json.RawMessage, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return []json.RawMessage{}, nil
	}
	if strings.HasPrefix(out, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(out), &arr); err != nil {
			return nil, err
		}
		if arr == nil {
			arr = []json.RawMessage{}
		}
		return arr, nil
	}
	items := make([]json.RawMessage, 0)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, err
		}
		items = append(items, raw)
	}
	return items, nil
}

// --- RBAC / 校验辅助 ---

// requireReader 校验 operator/admin(只读操作仍需登录主体有面板操作权)。失败已写响应。
func (m *Module) requireReader(w http.ResponseWriter, r *http.Request) bool {
	_, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return false
	}
	return true
}

// requireWriter 校验 operator/admin 并返回 uid。失败已写响应。
func (m *Module) requireWriter(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// requireAdmin 校验 admin 并返回 uid。失败已写响应。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// requireDanger 校验危险操作:需 admin + X-Confirm-Danger。失败已写响应。
func (m *Module) requireDanger(w http.ResponseWriter, r *http.Request) (int64, bool) {
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return 0, false
	}
	return m.requireAdmin(w, r)
}

// refParam 取 URL 路径中的 {ref} 并校验。失败已写 400。
func (m *Module) refParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	ref := chi.URLParamFromCtx(r.Context(), "ref")
	if !ValidRef(ref) {
		http.Error(w, "invalid container/image ref", http.StatusBadRequest)
		return "", false
	}
	return ref, true
}

// composeDir 取 {project},校验后解析为 compose 项目目录。失败已写响应。
func (m *Module) composeDir(w http.ResponseWriter, r *http.Request) (dir, project string, ok bool) {
	project = chi.URLParamFromCtx(r.Context(), "project")
	if !ValidProjectName(project) {
		http.Error(w, "invalid compose project name", http.StatusBadRequest)
		return "", "", false
	}
	set, err := m.ss.loadSettings()
	if err != nil {
		log.Printf("docker: load settings failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return "", "", false
	}
	dir, err = composeProjectDir(set.ComposeDir, project)
	if err != nil {
		http.Error(w, "invalid compose project name", http.StatusBadRequest)
		return "", "", false
	}
	return dir, project, true
}

// validDir 校验路径设置:非空、绝对路径、无控制字符。
func validDir(dir string) bool {
	dir = strings.TrimSpace(dir)
	if dir == "" || !strings.HasPrefix(dir, "/") {
		return false
	}
	for _, c := range dir {
		if c == '\n' || c == '\r' || c < 0x20 {
			return false
		}
	}
	return true
}

// cryptor 用 per-install secret 派生 AES-GCM,用于仓库凭证加解密。
func (m *Module) cryptor() (*cryptor, error) {
	secret, err := m.ss.installSecret()
	if err != nil {
		return nil, err
	}
	return newCryptor(secret)
}

// decodeJSON 解码受限大小的 JSON body,失败时写 400 并返回错误。
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return err
	}
	return nil
}

func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writePlain(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(s))
}

// clientIP 取真实客户端 IP:有受信代理感知的提取器则用之,否则回退 RemoteAddr。
func (m *Module) clientIP(r *http.Request) string {
	if m.deps.ClientIP != nil {
		return m.deps.ClientIP(r)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
