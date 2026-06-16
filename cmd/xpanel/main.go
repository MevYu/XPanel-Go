package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/config"
	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/modules/alert"
	"github.com/MevYu/XPanel-Go/internal/modules/antitamper"
	"github.com/MevYu/XPanel-Go/internal/modules/appstore"
	"github.com/MevYu/XPanel-Go/internal/modules/backup"
	"github.com/MevYu/XPanel-Go/internal/modules/cron"
	"github.com/MevYu/XPanel-Go/internal/modules/dashboard"
	"github.com/MevYu/XPanel-Go/internal/modules/database"
	"github.com/MevYu/XPanel-Go/internal/modules/dns"
	"github.com/MevYu/XPanel-Go/internal/modules/docker"
	"github.com/MevYu/XPanel-Go/internal/modules/files"
	"github.com/MevYu/XPanel-Go/internal/modules/firewall"
	"github.com/MevYu/XPanel-Go/internal/modules/ftp"
	"github.com/MevYu/XPanel-Go/internal/modules/java"
	"github.com/MevYu/XPanel-Go/internal/modules/loadbalancer"
	"github.com/MevYu/XPanel-Go/internal/modules/mail"
	"github.com/MevYu/XPanel-Go/internal/modules/malscan"
	"github.com/MevYu/XPanel-Go/internal/modules/memcached"
	"github.com/MevYu/XPanel-Go/internal/modules/migration"
	"github.com/MevYu/XPanel-Go/internal/modules/mysqlrepl"
	"github.com/MevYu/XPanel-Go/internal/modules/nodejs"
	"github.com/MevYu/XPanel-Go/internal/modules/php"
	"github.com/MevYu/XPanel-Go/internal/modules/python"
	"github.com/MevYu/XPanel-Go/internal/modules/security"
	"github.com/MevYu/XPanel-Go/internal/modules/service"
	"github.com/MevYu/XPanel-Go/internal/modules/sitemonitor"
	"github.com/MevYu/XPanel-Go/internal/modules/sites"
	"github.com/MevYu/XPanel-Go/internal/modules/ssl"
	"github.com/MevYu/XPanel-Go/internal/modules/supervisor"
	"github.com/MevYu/XPanel-Go/internal/modules/terminal"
	"github.com/MevYu/XPanel-Go/internal/modules/users"
	"github.com/MevYu/XPanel-Go/internal/modules/waf"
	"github.com/MevYu/XPanel-Go/internal/server"
	"github.com/MevYu/XPanel-Go/internal/store"
)

const version = "0.0.1"

func main() {
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o700); err != nil {
		log.Fatalf("mkdir data: %v", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	secret, err := cfg.DecodedSecret()
	if err != nil {
		log.Fatalf("jwt secret: %v", err)
	}
	jm := auth.NewJWTManager(secret)
	lo := auth.NewLockout(5, 5*time.Minute, time.Now)
	banGuard, err := auth.NewIPBanGuard(st, cfg.LoginMaxAttempts, time.Duration(cfg.IPBanHours)*time.Hour, time.Now)
	if err != nil {
		log.Fatalf("ip ban guard: %v", err)
	}
	svc := auth.NewService(st, jm, lo).WithIPBan(banGuard)

	// 首启:无用户则创建 admin,随机密码打印到 stdout(仅此一次)
	n, err := st.CountUsers()
	if err != nil {
		log.Fatalf("count users: %v", err)
	}
	if n == 0 {
		pw := randomPassword()
		if err := svc.Register("admin", pw, "admin"); err != nil {
			log.Fatalf("bootstrap admin: %v", err)
		}
		_ = st.WriteAudit(nil, "bootstrap.admin", "admin", "system")
		fmt.Printf("==== XPanel 首次启动 ====\n用户名: admin\n密码: %s\n入口地址: http://%s%s/\n(请立即登录并修改)\n", pw, cfg.Addr, cfg.NormalizedEntryPath())
	}

	auditFn := func(userID *int64, action, detail, ip string) {
		_ = st.WriteAudit(userID, action, detail, ip)
	}

	trustedProxies, err := cfg.ParseTrustedProxies()
	if err != nil {
		log.Fatalf("trusted_proxies: %v", err)
	}
	clientIP := func(r *http.Request) string { return server.ExtractClientIP(r, trustedProxies) }

	reg := module.NewRegistry()
	reg.Register(dashboard.New())
	reg.Register(service.New(service.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(cron.New(st, cron.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(firewall.New(firewall.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(terminal.New(terminal.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	filesMod, err := files.New("", st, files.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	})
	if err != nil {
		log.Fatalf("files module: %v", err)
	}
	reg.Register(filesMod)
	reg.Register(database.New(cfg.JWTSecret, st, database.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(sites.New(st, sites.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(ssl.New(st, nil, ssl.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(supervisor.New(st, supervisor.NewController(), supervisor.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(waf.New(st, waf.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(malscan.New(st, malscan.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(docker.New(st, docker.NewRunner(), docker.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(users.New(st, cfg.JWTSecret, users.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(ftp.New(st, nil, ftp.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(backup.New(cfg.JWTSecret, st, backup.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(php.New(st, nil, nil, php.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(nodejs.New(st, nodejs.NewSupervisorManager(), nodejs.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(python.New(st, python.NewProvisioner(), func(s python.Settings) python.Runner {
		return python.NewSupervisorRunner(s.ConfDir, s.LogDir)
	}, python.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(dns.New(cfg.JWTSecret, st, dns.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(security.New(st, nil, nil, nil, security.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(antitamper.New(st, antitamper.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(appstore.New(st, appstore.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(alert.New(cfg.JWTSecret, st, alert.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(java.New(st, java.NewSupervisorManager(), java.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(sitemonitor.New(st, nil, sitemonitor.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(migration.New(st, migration.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(mail.New(st, nil, mail.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(loadbalancer.New(st, loadbalancer.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(memcached.New(st, nil, memcached.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	reg.Register(mysqlrepl.New(cfg.JWTSecret, st, mysqlrepl.Deps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	}))
	registerOptionalModules(reg, st, optionalDeps{
		Principal: server.PrincipalFromRequest,
		Audit:     auditFn,
		ClientIP:  clientIP,
	})
	mgr := module.NewManager(reg, st)
	if err := mgr.Restore(); err != nil {
		log.Fatalf("module restore: %v", err)
	}
	loginTOTP := func(userID int64, code string) (enabled, ok bool, err error) {
		return users.VerifyLoginTOTP(st, cfg.JWTSecret, userID, code)
	}
	probeGuard := server.NewEntryProbeGuard(
		cfg.EntryProbeMax,
		time.Duration(cfg.EntryProbeWindowMinutes)*time.Minute,
		banGuard.Ban,
		time.Now,
	)
	h := server.NewWithModules(svc, jm, reg, mgr, loginTOTP, banGuard.Banned, trustedProxies, cfg.NormalizedEntryPath(), probeGuard)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second, // 防 Slowloris;不设 ReadTimeout/WriteTimeout 以兼容长连接 WS
		IdleTimeout:       120 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()
	fmt.Printf("XPanel %s 监听 http://%s\n", version, cfg.Addr)
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func randomPassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("generate password: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
