// Package webui serves the embedded SPA frontend (built into web/dist by
// scripts/build-release.sh). Without a real build, dist holds a placeholder
// index.html so the binary still compiles.
package webui

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves embedded static files; any path not matching a file falls
// back to index.html so the SPA can do client-side routing.
func Handler() http.Handler {
	return HandlerWithBase("/")
}

// HandlerWithBase serves the SPA under a hidden entry path. It serves
// /assets/* static files as-is and returns index.html for any other path
// (the SPA does client-side routing). The returned index.html has a
// window.__XPANEL_BASE__ script injected before </head> so the frontend can
// set its React Router basename to entryPath.
func HandlerWithBase(entryPath string) http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err) // embed guarantees dist exists; failure means a broken build
	}
	rawIndex, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic(err)
	}
	index := injectBase(rawIndex, entryPath)
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			serveIndex(w, index)
			return
		}
		if f, err := sub.Open(p); err == nil {
			if st, _ := f.Stat(); st != nil && !st.IsDir() {
				f.Close()
				// Vite emits content-hashed names under assets/; cache them hard.
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
			f.Close()
		}
		serveIndex(w, index)
	})
}

// injectBase 在 </head> 前插入 window.__XPANEL_BASE__ 脚本,供前端设置 basename。
func injectBase(index []byte, entryPath string) []byte {
	snippet := []byte(`<script>window.__XPANEL_BASE__="` + entryPath + `";</script>`)
	if i := bytes.Index(index, []byte("</head>")); i >= 0 {
		out := make([]byte, 0, len(index)+len(snippet))
		out = append(out, index[:i]...)
		out = append(out, snippet...)
		out = append(out, index[i:]...)
		return out
	}
	// 无 </head>(占位 index 也有):退化为前置注入,仍保证 base 可用。
	return append(snippet, index...)
}

func serveIndex(w http.ResponseWriter, index []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(index)
}
