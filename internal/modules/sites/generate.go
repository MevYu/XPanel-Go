package sites

import (
	"fmt"
	"strings"
)

// generateConfig 从 SiteConfig 组合完整 nginx 配置文本。
//
// 安全模型(同既有 vhost.go):所有动态字段在入站处经白名单校验,绝不含换行/元字符;
// 本函数渲染前再调 assertConfigNoInjection 兜底,任何字段含控制字符即拒绝(不应发生)。
// 真正的语法把关在写盘后的 nginx -t。
//
// SSL 开启时输出两个 server 块:80 块(ForceHTTPS 则 301 跳 443,否则正常提供内容)
// 和 443 ssl 块(含证书、可选 HSTS)。两块共享同一套 location 逻辑。
func generateConfig(c SiteConfig) (string, error) {
	if err := assertConfigNoInjection(c); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("# Managed by XPanel sites module. Do not edit by hand.\n")

	if c.Kind == KindProxy && len(c.Proxy.Upstreams) > 1 {
		fmt.Fprintf(&b, "upstream xpanel_%s {\n", c.Name)
		for _, up := range c.Proxy.Upstreams {
			fmt.Fprintf(&b, "    server %s;\n", trimScheme(up))
		}
		b.WriteString("}\n")
	} else if c.Kind == KindProxy && c.Upstream != "" {
		fmt.Fprintf(&b, "upstream xpanel_%s {\n    server %s;\n}\n", c.Name, trimScheme(c.Upstream))
	}

	httpPort := primaryPort(c.Domains)

	if c.SSL.Enabled {
		// 80 块:强制跳转或正常服务。
		writeServerOpen(&b, httpPort, c.Domains, c)
		if c.SSL.ForceHTTPS {
			b.WriteString("    return 301 https://$host$request_uri;\n")
		} else {
			writeServerBody(&b, c)
		}
		b.WriteString("}\n")

		// 443 ssl 块。
		writeServerOpenTLS(&b, c)
		writeServerBody(&b, c)
		b.WriteString("}\n")
	} else {
		writeServerOpen(&b, httpPort, c.Domains, c)
		writeServerBody(&b, c)
		b.WriteString("}\n")
	}

	out := b.String()
	// 渲染后整体复扫:确保无裸 CR/NUL 漏入(校验层已挡,双保险)。
	if err := validNginxFragment(out); err != nil {
		return "", err
	}
	return out, nil
}

// writeServerOpen 写 server 块开头(监听 + server_name + 日志)。
func writeServerOpen(b *strings.Builder, port int, domains []Domain, c SiteConfig) {
	b.WriteString("server {\n")
	fmt.Fprintf(b, "    listen %d;\n", port)
	fmt.Fprintf(b, "    server_name%s;\n", domainNames(domains))
	if c.AccessLog != "" {
		fmt.Fprintf(b, "    access_log %s;\n", c.AccessLog)
	}
	if c.ErrorLog != "" {
		fmt.Fprintf(b, "    error_log %s;\n", c.ErrorLog)
	}
}

// writeServerOpenTLS 写 443 ssl server 块开头(含证书与可选 HSTS)。
func writeServerOpenTLS(b *strings.Builder, c SiteConfig) {
	b.WriteString("server {\n")
	b.WriteString("    listen 443 ssl;\n")
	fmt.Fprintf(b, "    server_name%s;\n", domainNames(c.Domains))
	fmt.Fprintf(b, "    ssl_certificate %s;\n", c.SSL.CertPath)
	fmt.Fprintf(b, "    ssl_certificate_key %s;\n", c.SSL.KeyPath)
	b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
	b.WriteString("    ssl_ciphers HIGH:!aNULL:!MD5;\n")
	if c.SSL.HSTS {
		b.WriteString("    add_header Strict-Transport-Security \"max-age=31536000\" always;\n")
	}
	if c.AccessLog != "" {
		fmt.Fprintf(b, "    access_log %s;\n", c.AccessLog)
	}
	if c.ErrorLog != "" {
		fmt.Fprintf(b, "    error_log %s;\n", c.ErrorLog)
	}
}

// writeServerBody 写 server 块主体:root/index、重定向、目录保护、防盗链、
// 主 location(rewrite 优先)、php fastcgi、proxy、custom_config。
func writeServerBody(b *strings.Builder, c SiteConfig) {
	if c.Root != "" {
		fmt.Fprintf(b, "\n    root %s;\n", c.Root)
	}
	if len(c.IndexDocs) > 0 {
		fmt.Fprintf(b, "    index %s;\n", strings.Join(c.IndexDocs, " "))
	}

	writeRedirects(b, c.Redirects)
	writeDirProtect(b, c)
	writeAntiLeech(b, c.AntiLeech)

	// 主 location:有伪静态则用之,否则按类型默认。
	switch c.Kind {
	case KindProxy:
		b.WriteString("\n    location / {\n")
		if len(c.Proxy.Upstreams) > 1 {
			fmt.Fprintf(b, "        proxy_pass http://xpanel_%s;\n", c.Name)
		} else {
			fmt.Fprintf(b, "        proxy_pass %s;\n", c.Upstream)
		}
		hostVal := "$host"
		if c.Proxy.SendHost != "" {
			hostVal = c.Proxy.SendHost
		}
		fmt.Fprintf(b, "        proxy_set_header Host %s;\n", hostVal)
		b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		if c.Proxy.WebSocket {
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
			b.WriteString("        proxy_set_header Connection \"upgrade\";\n")
		}
		for _, h := range c.Proxy.SetHeaders {
			fmt.Fprintf(b, "        proxy_set_header %s %s;\n", h.Name, h.Value)
		}
		if c.Proxy.Cache {
			fmt.Fprintf(b, "        proxy_cache_valid 200 %ds;\n", c.Proxy.CacheTime)
		}
		b.WriteString("    }\n")
	default:
		if strings.TrimSpace(c.RewriteRules) != "" {
			b.WriteString("\n")
			writeIndented(b, c.RewriteRules, "    ")
			b.WriteString("\n")
		} else if c.Kind == KindPHP {
			b.WriteString("\n    location / {\n        try_files $uri $uri/ /index.php?$query_string;\n    }\n")
		} else {
			b.WriteString("\n    location / {\n        try_files $uri $uri/ =404;\n    }\n")
		}
		if c.Kind == KindPHP {
			b.WriteString("\n    location ~ [.]php$ {\n")
			b.WriteString("        include fastcgi_params;\n")
			fmt.Fprintf(b, "        fastcgi_pass unix:%s;\n", c.PHPSocket)
			b.WriteString("        fastcgi_index index.php;\n")
			b.WriteString("        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n")
			b.WriteString("    }\n")
		}
	}

	if strings.TrimSpace(c.CustomConfig) != "" {
		b.WriteString("\n")
		writeIndented(b, c.CustomConfig, "    ")
		b.WriteString("\n")
	}
}

func writeRedirects(b *strings.Builder, rs []Redirect) {
	for _, r := range rs {
		fmt.Fprintf(b, "\n    location %s {\n        return %d %s;\n    }\n", r.From, r.Code, r.To)
	}
}

func writeDirProtect(b *strings.Builder, c SiteConfig) {
	if len(c.DirProtect) == 0 {
		return
	}
	// 同站点所有保护项共用一个 .htpasswd 文件(按站点名)。
	file := fmt.Sprintf("%s/%s.htpasswd", c.HtpasswdDir, c.Name)
	seen := map[string]bool{}
	for _, d := range c.DirProtect {
		if seen[d.Path] {
			continue // 同 path 只生成一个 location 块
		}
		seen[d.Path] = true
		fmt.Fprintf(b, "\n    location %s {\n", d.Path)
		b.WriteString("        auth_basic \"Restricted\";\n")
		fmt.Fprintf(b, "        auth_basic_user_file %s;\n", file)
		b.WriteString("    }\n")
	}
}

func writeAntiLeech(b *strings.Builder, a AntiLeech) {
	if !a.Enabled || len(a.Extensions) == 0 {
		return
	}
	fmt.Fprintf(b, "\n    location ~* [.](%s)$ {\n", strings.Join(a.Extensions, "|"))
	refs := append([]string{"none", "blocked"}, a.AllowedReferers...)
	fmt.Fprintf(b, "        valid_referers %s;\n", strings.Join(refs, " "))
	b.WriteString("        if ($invalid_referer) {\n            return 403;\n        }\n")
	b.WriteString("    }\n")
}

// writeIndented 把多行片段按每行加前缀缩进写入(保持片段内相对缩进)。
func writeIndented(b *strings.Builder, frag, prefix string) {
	for i, line := range strings.Split(strings.TrimRight(frag, "\n"), "\n") {
		if i > 0 {
			b.WriteByte('\n')
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		b.WriteString(prefix)
		b.WriteString(line)
	}
}

// domainNames 返回 " a.com b.com" 形式(前导空格便于拼接)。去重保持顺序。
func domainNames(ds []Domain) string {
	seen := map[string]bool{}
	var sb strings.Builder
	for _, d := range ds {
		if seen[d.Domain] {
			continue
		}
		seen[d.Domain] = true
		sb.WriteByte(' ')
		sb.WriteString(d.Domain)
	}
	return sb.String()
}

// primaryPort 取域名列表中的非 443 监听端口(默认 80)。
func primaryPort(ds []Domain) int {
	for _, d := range ds {
		if d.Port != 0 && d.Port != 443 {
			return d.Port
		}
	}
	return 80
}

func trimScheme(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		return u[i+3:]
	}
	return u
}

// assertConfigNoInjection 渲染前断言:所有进入配置的动态字段不含控制字符。
// rewrite/custom 片段允许换行(多行指令),但其余字段(域名/路径/扩展名等)严禁换行。
func assertConfigNoInjection(c SiteConfig) error {
	strict := []string{c.Name, c.Root, c.PHPVersion, c.PHPSocket, c.Upstream,
		c.AccessLog, c.ErrorLog, c.HtpasswdDir, c.SSL.CertPath, c.SSL.KeyPath}
	strict = append(strict, c.IndexDocs...)
	strict = append(strict, c.Proxy.Upstreams...)
	strict = append(strict, c.Proxy.SendHost)
	for _, h := range c.Proxy.SetHeaders {
		strict = append(strict, h.Name, h.Value)
	}
	for _, d := range c.Domains {
		strict = append(strict, d.Domain)
	}
	for _, r := range c.Redirects {
		strict = append(strict, r.From, r.To)
	}
	for _, d := range c.DirProtect {
		strict = append(strict, d.Path, d.Username, d.PassHash)
	}
	for _, e := range c.AntiLeech.Extensions {
		strict = append(strict, e)
		if !validExtension(e) {
			return fmt.Errorf("invalid anti-leech extension %q", e)
		}
	}
	for _, r := range c.AntiLeech.AllowedReferers {
		strict = append(strict, r)
		if !validReferer(r) {
			return fmt.Errorf("invalid anti-leech referer %q", r)
		}
	}
	for _, f := range strict {
		if strings.ContainsAny(f, "\n\r") {
			return fmt.Errorf("config field contains control character")
		}
	}
	// 片段字段:允许换行,但拒绝 NUL / 裸 CR。
	if err := validNginxFragment(c.RewriteRules); err != nil {
		return err
	}
	if err := validNginxFragment(c.CustomConfig); err != nil {
		return err
	}
	return nil
}
