package sites

import (
	"fmt"
	"path/filepath"
	"strings"
)

// phpSocketFor 把 PHP 版本解析为 fastcgi unix socket 路径。
// 版本空 → 回退设置里的默认 socket。版本格式由 validPHPVersion 把关。
// 约定路径形如 /run/php/php<ver>-fpm.sock(对标 Debian/Ubuntu PHP-FPM 命名)。
func phpSocketFor(version string, set Settings) (string, error) {
	if strings.TrimSpace(version) == "" {
		return set.PHPSocket, nil
	}
	if !validPHPVersion(version) {
		return "", fmt.Errorf("invalid php version %q", version)
	}
	sock := fmt.Sprintf("/run/php/php%s-fpm.sock", version)
	if err := validPHPSock(sock); err != nil {
		return "", err
	}
	return sock, nil
}

// siteToConfig 把持久化的 Site + 全局设置组装为可渲染的 SiteConfig。
// 不做白名单校验(写入时已校验);仅解析 php socket 与 htpasswd 目录等派生字段。
func siteToConfig(st Site, set Settings) (SiteConfig, error) {
	cfg := SiteConfig{
		Name:         st.Name,
		Domains:      st.DomainBindings,
		Kind:         SiteKind(st.Kind),
		Root:         st.RootDir,
		PHPVersion:   st.PHPVersion,
		IndexDocs:    st.IndexDocs,
		Upstream:     st.ProxyTarget,
		RewriteRules: st.RewriteRules,
		SSL:          st.SSL,
		DirProtect:   st.DirProtect,
		Redirects:    st.Redirects,
		AntiLeech:    st.AntiLeech,
		CustomConfig: st.CustomConfig,
		AccessLog:    st.AccessLog,
		ErrorLog:     st.ErrorLog,
		HtpasswdDir:  htpasswdDir(set),
	}
	if cfg.Kind == KindPHP {
		sock, err := phpSocketFor(st.PHPVersion, set)
		if err != nil {
			return SiteConfig{}, err
		}
		cfg.PHPSocket = sock
	}
	return cfg, nil
}

// htpasswdDir 是 .htpasswd 文件目录,放在 conf 目录下的 htpasswd 子目录。
func htpasswdDir(set Settings) string {
	return filepath.Join(set.ConfDir, "htpasswd")
}

// safeRunDir 把站点根下的子目录解析为绝对运行目录,拒绝穿越出站点根。
// subdir 空则返回站点根本身。
func safeRunDir(webRoot, name, subdir string) (string, error) {
	root, err := safeWebRoot(webRoot, name)
	if err != nil {
		return "", err
	}
	subdir = strings.Trim(strings.TrimSpace(subdir), "/")
	if subdir == "" {
		return root, nil
	}
	if strings.Contains(subdir, "..") || strings.ContainsAny(subdir, " \t\n\r;{}$*?\"'`\\") {
		return "", fmt.Errorf("invalid run dir %q", subdir)
	}
	joined := filepath.Clean(filepath.Join(root, subdir))
	if !strings.HasPrefix(joined, root+string(filepath.Separator)) {
		return "", fmt.Errorf("run dir escapes site root")
	}
	return joined, nil
}

// writeCertPair 把上传的 PEM 写盘并返回两文件路径。cert/key 都必须非空。
func writeCertPair(ng Nginx, set Settings, name, certPEM, keyPEM string) (string, string, error) {
	if strings.TrimSpace(certPEM) == "" || strings.TrimSpace(keyPEM) == "" {
		return "", "", fmt.Errorf("both cert_pem and key_pem are required")
	}
	if !strings.Contains(certPEM, "-----BEGIN") || !strings.Contains(keyPEM, "-----BEGIN") {
		return "", "", fmt.Errorf("cert_pem/key_pem must be PEM encoded")
	}
	return ng.WriteCert(name, certPEM, keyPEM)
}

// domainsOf 从绑定列表抽取纯域名(去重),供 Site.Domains 兼容字段与 server_name 使用。
func domainsOf(bs []Domain) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range bs {
		if seen[b.Domain] {
			continue
		}
		seen[b.Domain] = true
		out = append(out, b.Domain)
	}
	return out
}
