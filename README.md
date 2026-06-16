# XPanel-Go

单二进制、零依赖的 Linux 服务器运维面板。模块化按需启用、安全优先,对标 aaPanel / 1Panel。

后端用 Go 编写，前端 SPA 通过 `go:embed` 打进同一个可执行文件 —— 部署只需一个二进制 + 一个 systemd 单元。

## 核心卖点

- **单二进制零依赖**：前端构建产物嵌入二进制，`CGO_ENABLED=0` 静态编译，落地即跑（SQLite 用纯 Go 的 modernc 驱动，无需 libc）。
- **模块化按需启用**：32 个功能模块编译期注册、运行期开关，默认全部关闭（`dashboard` 除外），用多少开多少。
- **安全优先**：argon2id 口令、钉死 HS256 的可撤销 JWT、登录 2FA、RBAC、全量审计、命令执行无 shell 注入、敏感凭证 AES-GCM 加密。
- **默认只绑回环**：默认监听 `127.0.0.1:8765`，对外暴露须自行反代加 TLS。

## 功能模块

按分类列出全部 32 个模块（模块 ID / 名称）：

**系统**
`dashboard` 系统总览（常驻） · `service` 服务管理 · `cron` 定时任务 · `terminal` Web 终端 · `files` 文件管理 · `supervisor` 进程守护 · `backup` 备份 · `alert` 监控告警 · `migration` 一键迁移 · `fleet` 集群（需 `-tags fleet`）

**网站**
`sites` 网站 · `ssl` SSL 证书 · `dns` DNS · `ftp` FTP · `php` PHP · `nodejs` Node 项目 · `python` Python 项目 · `java` Java 项目 · `loadbalancer` 负载均衡 · `sitemonitor` 网站监控 · `mail` 邮局

**数据库**
`database` 数据库 · `mysqlrepl` MySQL 主从 · `memcached` Memcached

**安全**
`firewall` 防火墙 · `waf` 网站防火墙 · `security` 安全加固 · `antitamper` 防篡改 · `malscan` 木马查杀 · `users` 用户

**应用**
`docker` 容器 · `appstore` 应用商店

## 安装

一键安装（aaPanel 风格，需 root）：

```bash
curl -fsSL https://raw.githubusercontent.com/MevYu/XPanel-Go/main/scripts/install.sh | bash
```

从源码安装（自动拉取后端 + 前端仓库并构建，需 `go` 与 `npm`）：

```bash
curl -fsSL https://raw.githubusercontent.com/MevYu/XPanel-Go/main/scripts/install.sh | bash -s -- --from-source
```

带多机集群功能：追加 `--fleet`。

安装脚本会：把二进制装到 `/usr/local/bin/xpanel`，数据目录设为 `/opt/xpanel`，安装并启动 systemd 单元 `xpanel.service`，并从服务日志中抓取**首次启动的 admin 凭证**打印出来。

**系统要求**：Linux（amd64 / arm64）、root 权限（面板要管理宿主机的服务、防火墙、文件）。

**首次启动**：无任何用户时自动创建 `admin`，随机密码仅打印一次（到 stdout / 服务日志），请立即登录并修改。

**网络**：默认绑定 `127.0.0.1:8765`，仅本机可达。对外访问请用 Nginx/Caddy 反代并配 TLS。监听地址在 `config.json` 的 `addr` 字段调整。

## 从源码构建

前端来自配套仓库 [XPanel-Web](https://github.com/MevYu/XPanel-Web)，默认与本仓库同级（`../XPanel-Web`）。

```bash
make build        # 默认构建,不含 fleet,输出 ./xpanel
make build-full   # 带 -tags fleet,含多机集群模块
make release      # 跨架构(amd64/arm64)+ 前端嵌入,产物在 ./release
make run          # 直接 go run
```

`make build` 不要求前端已构建：`web/dist` 内置占位 `index.html` 保证二进制可编译。完整前端由 `make release`（即 `scripts/build-release.sh`）在 XPanel-Web 里 `npm run build` 后拷入 `web/dist` 再嵌入。

## 架构简述

- **模块系统**：每个模块实现 `module.Module` 接口，编译期在 `cmd/xpanel/main.go` 注册进 `Registry`；运行期由 `Manager` 按持久化状态开关。模块路由统一挂在 `/api/m/<id>/` 命名空间下，外包一层启用门（停用即 404）。
- **公开路由**：需绕过面板登录的端点（文件外链、WS-ticket）由模块实现 `PublicRouter`，经 `MountPublic` 挂在 `/s/` 等前缀下，由模块自身 token/ticket 鉴权。
- **build-tag 可选模块**：`fleet`（多机集群，依赖 NATS）通过 `-tags fleet` 编译期可选，默认构建不含它，保持二进制精简。`fleet` agent 模式由 `--mode=agent` 启动。
- **单二进制**：前端 SPA 经 `go:embed all:dist` 打进二进制；非 API 路由全部回退到 `index.html`，支持前端客户端路由。

## 安全特性

- 口令哈希：**argon2id**。
- 会话：JWT 钉死 **HS256**，拒绝 `alg=none` 与其他算法降级；refresh token 可撤销。
- 登录 **2FA**（TOTP）。
- **RBAC**：危险操作要求 admin 角色。
- **审计**：关键动作写审计日志（含操作者、动作、IP）。
- **命令执行注入安全**：调用外部命令一律用参数数组，绝不拼 shell 字符串。
- **SQL 标识符白名单**：动态表名/列名走白名单校验，杜绝注入。
- **凭证 AES-GCM 加密**：第三方凭证（DNS API key、备份目标、主从密码等）加密落库。
- **每模块可配置路径**：路径类配置经各模块的设置端点管理，不写死。
- systemd 单元已加固（`NoNewPrivileges`、`ProtectSystem=full`、`ProtectHome`、`PrivateTmp`、`UMask=0077`）。

## 配套前端

UI 在独立仓库 [XPanel-Web](https://github.com/MevYu/XPanel-Web)（Vite SPA）。`make release` 会构建并把产物嵌入后端二进制；开发时也可单独跑前端 dev server 指向后端 API。

## 许可

见 [LICENSE](./LICENSE)。
