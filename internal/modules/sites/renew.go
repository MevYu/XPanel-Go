package sites

import (
	"context"
	"log"
	"strings"
	"time"
)

// renewWindow 是续期阈值:证书到期前 30 天内即触发重签。
const renewWindow = 30 * 86400

// certDueForRenewal 判定证书是否进入续期窗口(到期前不足 30 天)。
func certDueForRenewal(expiresAt, now int64) bool {
	return expiresAt > 0 && expiresAt-now < renewWindow
}

// renewLoop 每日触发一次续期巡检,直到 stopCh 关闭。
func (m *Module) renewLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			m.renewDueCerts(context.Background())
		}
	}
}

// renewDueCerts 扫描所有 ACME 签发且临近到期的站点,重签证书 → 重渲染 → reload → 落库。
// 单站点失败只记日志不中断其它站点。
func (m *Module) renewDueCerts(ctx context.Context) {
	sites, err := m.ss.list()
	if err != nil {
		log.Printf("sites: renew list failed: %v", err)
		return
	}
	set, err := m.ss.getSettings()
	if err != nil {
		log.Printf("sites: renew settings load failed: %v", err)
		return
	}
	now := time.Now().Unix()
	for _, site := range sites {
		if !site.SSL.Enabled || site.SSL.ACMEEmail == "" || !certDueForRenewal(site.SSL.ExpiresAt, now) {
			continue
		}
		if err := m.renewOne(ctx, site, set); err != nil {
			log.Printf("sites: renew %q failed: %v", site.Name, err)
		}
	}
}

// renewOne 为单个站点重签并应用。
func (m *Module) renewOne(ctx context.Context, site Site, set Settings) error {
	webroot := site.RootDir
	if webroot == "" {
		wr, err := safeWebRoot(set.WebRoot, site.Name)
		if err != nil {
			return err
		}
		webroot = wr
	}
	ng := m.newNginx(set.ConfDir)

	ictx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	certPEM, keyPEM, err := m.newIssuer().Issue(ictx, site.SSL.ACMEEmail, site.SSL.ACMEDomains,
		func(token, keyAuth string) error { return ng.WriteChallenge(webroot, token, keyAuth) },
		func(token string) { _ = ng.RemoveChallenge(webroot, token) })
	if err != nil {
		return err
	}
	certPath, keyPath, err := ng.WriteCert(site.Name, certPEM, keyPEM)
	if err != nil {
		return err
	}
	expiresAt, err := certNotAfter(certPEM)
	if err != nil {
		return err
	}
	site.SSL.CertPath = certPath
	site.SSL.KeyPath = keyPath
	site.SSL.ExpiresAt = expiresAt

	cfg, err := siteToConfig(site, set)
	if err != nil {
		return err
	}
	config, err := generateConfig(cfg)
	if err != nil {
		return err
	}
	site.Config = config
	if site.Enabled {
		if err := m.writeAndReload(ng, site.Name, config); err != nil {
			return err
		}
	}
	if err := m.ss.update(site); err != nil {
		return err
	}
	m.deps.Audit(nil, "sites.ssl.renew", site.Name+" "+strings.Join(site.SSL.ACMEDomains, ","), "")
	return nil
}
