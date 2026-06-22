# XPanel-Go

单二进制 Linux 运维面板：模块化按需启用，前端 SPA 嵌入二进制。

## 技术栈

- Go 1.26，路由 `go-chi/chi/v5`，SQLite 用纯 Go 驱动 `modernc.org/sqlite`（`CGO_ENABLED=0` 可静态编译）。
- 关键依赖：`golang-jwt/jwt/v5`（HS256）、`golang.org/x/crypto`（argon2id）、`pquerna/otp`（TOTP）、`coder/websocket` + `creack/pty`（Web 终端）、`shirou/gopsutil`（指标）、`nats-io/*`（仅 fleet）。
- 前端在独立仓库 XPanel-Web，构建产物经 `go:embed` 进 `web/dist`。

## 常用命令

```bash
make build        # 默认构建,不含 fleet -> ./xpanel
make build-full   # go build -tags fleet,含 fleet 集群
make release      # 跨架构 + 前端嵌入 -> ./release
make run          # go run ./cmd/xpanel
go test ./... -race          # 默认构建测试
go test -tags fleet ./...    # 含 fleet 的测试
go vet ./...
govulncheck ./...            # 漏洞扫描
```

## 项目结构

- `cmd/xpanel/` —— main：加载 config、开 store、装配 auth、注册全部模块、`registerOptionalModules`（fleet 走 build tag）、`mgr.Restore()`、启服。`agent_fleet.go` 提供 `--mode=agent`（仅 fleet）。
- `internal/module/` —— 模块系统核心：`Module` 接口、`Registry`（编译期注册）、`Manager`（运行期开关 + Restore）、`gate`（启用门）、`MountPublic`（公开路由）。
- `internal/server/` —— HTTP 装配：中间件链（`SecurityHeaders` + 限流）、`NewWithModules`、`PrincipalFromRequest`、auth handlers、SPA 回退。
- `internal/store/` —— SQLite 封装；`migrations.go` 只含核心表（users / refresh_tokens / audit_log / module_state）。
- `internal/auth/` —— 口令（argon2id）、JWT（HS256）、登录锁定、Service。
- `internal/system/` —— 宿主操作原语：systemctl、crontab、firewall、metrics、pty、`safepath`（路径越界防护）。
- `internal/config/` —— `config.json` 读写，首启随机生成 JWT 密钥。
- `internal/modules/<id>/` —— 各功能模块，每个一个包。
- `web/` —— `embed.go` 嵌入 SPA；`dist/` 占位或真实前端。
- `scripts/` —— `build-release.sh`（跨架构 + 嵌前端 + 打包）、`install.sh`（一键装）、`xpanel.service`（加固过的 systemd 单元）。

## 架构约定

- 新模块 = `internal/modules/<id>/`，实现 `module.Module`（`Meta/Routes/Nav/Start/Stop/HealthCheck`）。
- 模块路由统一挂 `/api/m/<id>/` 命名空间，由 `Manager` 加启用门（停用即 404）。
- 宿主能力经 `Deps{Principal, Audit}` 注入模块，不在模块里直接依赖 server 内部。
- 模块自建数据表用 `CREATE TABLE IF NOT EXISTS`（幂等）在自己包里管，**不动** `internal/store/migrations.go` 的中央迁移。
- 路径类配置经各模块的设置端点管理，可配置、不写死。
- 需绕过面板登录的端点实现 `PublicRouter`，经 `MountPublic` 挂在 `PublicPrefix()`（如 `/s/`）下，模块自鉴权（token/ticket）。
- fleet（多机集群，依赖 NATS）走 `-tags fleet`，默认构建不编入。
- 模块 `Meta().ID` 重复会 panic（启动期暴露）。
- `HealthCheck()` 返回依赖的宿主软件是否安装/就绪（经 `/api/modules` 的 `health.{ok,reason}` 暴露，前端 `InstallGate` 据此盖"未安装"遮罩）；失败不阻止启用，仅作前端提示。探测软件存在性用 `exec.LookPath` / 连 socket / `systemctl`，参数数组、带超时、失败降级。

## 注意事项

- 调外部命令必传参数数组（`exec.Command(name, args...)`），**绝不拼 shell 字符串**。
- 动态 SQL 标识符（表名/列名）走白名单校验。
- 第三方凭证 AES-GCM 加密落库，绝不明文。
- 危险操作要求 admin + `X-Confirm-Danger` 头 + 写审计。
- `Start`/`Stop`/`HealthCheck` 在 Manager 持锁期间被调用，**必须快速返回**；长任务丢进 detached goroutine。
- 模块默认关闭，仅 `dashboard`（AlwaysOn）开机即启。
- 默认绑 `127.0.0.1:8765`，不绑 `0.0.0.0`。
- JWT 只接受 HS256，拒绝 `alg=none` 与其他算法。

## 不要做的事

- 不拼 shell 执行命令。
- 不明文存任何凭证。
- 不往 `internal/store/migrations.go` 加模块自己的表。
- 不破坏默认构建：默认产物**不得**含 fleet / NATS。
