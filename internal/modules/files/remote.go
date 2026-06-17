package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// maxRemoteBytes 是远程下载的大小上限,挡塞满磁盘。
const maxRemoteBytes = 512 << 20 // 512 MiB

// remoteTimeout 是单次远程下载的总超时。
const remoteTimeout = 60 * time.Second

// errBlockedAddr 表示目标 IP 命中 SSRF 黑名单(回环/私网/链路本地/元数据等)。
var errBlockedAddr = errors.New("blocked address")

type remoteDownloadReq struct {
	URL  string `json:"url"`
	Dest string `json:"dest"` // 目标目录(相对面板根)
	Name string `json:"name"` // 可选;留空从 URL 推断
}

func (m *Module) handleRemoteDownload(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Confirm-Danger") == "" {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var req remoteDownloadReq
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "url must be http or https", http.StatusBadRequest)
		return
	}
	// 文件名:显式优先,否则取 URL path 的 base;再 filepath.Base 防穿越。
	name := req.Name
	if name == "" {
		name = filepath.Base(u.Path)
	}
	name = filepath.Base(filepath.Clean("/" + name))
	if name == "" || name == "." || name == "/" {
		http.Error(w, "cannot determine file name", http.StatusBadRequest)
		return
	}
	dest, err := m.resolve(filepath.Join(req.Dest, name))
	if err != nil {
		pathError(w, err)
		return
	}

	resp, err := m.httpGet(req.URL)
	if err != nil {
		if errors.Is(err, errBlockedAddr) {
			m.audit(r, "files.remote_download.blocked", req.URL)
			http.Error(w, "destination address not allowed", http.StatusForbidden)
			return
		}
		http.Error(w, "remote fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "remote returned "+resp.Status, http.StatusBadGateway)
		return
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		fsError(w, err)
		return
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		fsError(w, err)
		return
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(resp.Body, maxRemoteBytes+1))
	if err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	if n > maxRemoteBytes {
		out.Close()
		_ = os.Remove(dest)
		http.Error(w, "remote file exceeds size limit", http.StatusRequestEntityTooLarge)
		return
	}
	m.audit(r, "files.remote_download", req.URL+" -> "+filepath.Join(req.Dest, name))
	w.WriteHeader(http.StatusNoContent)
}

// safeHTTPGet 抓取 url,在 TCP 拨号阶段拒绝任何指向内网/回环/链路本地/元数据的地址,
// 且禁止跨协议重定向到 http/https 之外。每一跳的目标 IP 都在 DialContext 里复核,
// 因此 DNS rebinding / 重定向到内网都挡得住。
func safeHTTPGet(rawURL string) (*http.Response, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if isBlockedIP(ip.IP) {
					return nil, errBlockedAddr
				}
			}
			// 用已解析、已校验的首个 IP 拨号,避免解析-拨号之间被换地址(TOCTOU)。
			d := &net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	client := &http.Client{
		Timeout:   remoteTimeout,
		Transport: transport,
		CheckRedirect: func(reqr *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if reqr.URL.Scheme != "http" && reqr.URL.Scheme != "https" {
				return fmt.Errorf("%w: cross-protocol redirect", errBlockedAddr)
			}
			return nil
		},
	}
	return client.Get(rawURL)
}

// isBlockedIP 判定 IP 是否属于禁止访问的网段:回环、私网(RFC1918/ULA)、
// 链路本地(含 169.254.169.254 元数据)、未指定、组播、保留。
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// IPv4 元数据 169.254.169.254 已被 IsLinkLocalUnicast 覆盖;
	// 显式再挡一道,兼顾可读性。
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	// IPv4 保留段 0.0.0.0/8、100.64.0.0/10(CGNAT)、192.0.0.0/24 等。
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0:
			return true
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64.0.0/10
			return true
		}
	}
	return false
}
