package database

import (
	"compress/gzip"
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// 导出/导入上限与超时。导入体上限防止 OOM/磁盘塞满;dump 超时防止挂死。
const (
	maxImportBytes  = 512 << 20 // 512 MiB
	transferTimeout = 30 * time.Minute
)

// handleExport 导出某库为 .sql 流式下载。?database=NAME 必填,?gzip=1 则 gzip 压缩。
// admin 即可(读取数据);写审计。
func (m *Module) handleExport(d dialect) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, role := m.deps.Principal(r)
		if role != "admin" {
			http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
			return
		}
		db := r.URL.Query().Get("database")
		if !validIdent(db) {
			http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
			return
		}
		eff, err := m.ss.effective()
		if err != nil {
			log.Printf("database: settings load failed: %v", err)
			http.Error(w, "settings unavailable", http.StatusInternalServerError)
			return
		}
		gz := r.URL.Query().Get("gzip") == "1"
		filename := db + ".sql"
		if gz {
			filename += ".gz"
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)

		ctx, cancel := context.WithTimeout(r.Context(), transferTimeout)
		defer cancel()

		var out io.Writer = w
		var gzw *gzip.Writer
		if gz {
			gzw = gzip.NewWriter(w)
			out = gzw
		}
		err = m.dumpRun.export(ctx, d, db, eff, out)
		if gzw != nil {
			// 即便 export 出错也要关闭 gzw 以 flush 已写部分;关闭错误不覆盖 export 错误。
			if cerr := gzw.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		outcome := "ok"
		if err != nil {
			outcome = "failed"
		}
		m.deps.Audit(&uid, m.engineName(d)+".export", "db="+db+" "+outcome, m.clientIP(r))
		if err != nil {
			// 头已发出(可能已写部分 body),无法再改状态码;记录并截断。
			log.Printf("database: %s export %s failed: %v", m.engineName(d), db, err)
			return
		}
	}
}

// handleImport 从上传的 .sql(支持 gzip)导入到库。危险操作:admin + X-Confirm-Danger + 审计。
// ?database=NAME 必填;?gzip=1 表示请求体为 gzip。请求体上限 maxImportBytes。
func (m *Module) handleImport(d dialect) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, role := m.deps.Principal(r)
		if role != "admin" {
			http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
			return
		}
		if !confirmed(r) {
			http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
			return
		}
		db := r.URL.Query().Get("database")
		if !validIdent(db) {
			http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
			return
		}
		eff, err := m.ss.effective()
		if err != nil {
			log.Printf("database: settings load failed: %v", err)
			http.Error(w, "settings unavailable", http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), transferTimeout)
		defer cancel()

		body := http.MaxBytesReader(w, r.Body, maxImportBytes)
		defer body.Close()
		var src io.Reader = body
		if r.URL.Query().Get("gzip") == "1" {
			gzr, gerr := gzip.NewReader(body)
			if gerr != nil {
				http.Error(w, "invalid gzip body", http.StatusBadRequest)
				return
			}
			defer gzr.Close()
			src = gzr
		}
		err = m.dumpRun.importSQL(ctx, d, db, eff, src)
		outcome := "ok"
		if err != nil {
			outcome = "failed"
		}
		m.deps.Audit(&uid, m.engineName(d)+".import", "db="+db+" "+outcome, m.clientIP(r))
		if err != nil {
			log.Printf("database: %s import %s failed: %v", m.engineName(d), db, err)
			http.Error(w, "import failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// redisConfigKeys 是 CONFIG GET 的常用项白名单(逐项查询,值汇总返回)。
var redisConfigKeys = []string{
	"maxmemory", "maxmemory-policy", "maxclients", "timeout",
	"save", "appendonly", "appendfsync", "databases", "bind", "tcp-keepalive",
}

// handleRedisConfig 返回常用配置项(CONFIG GET 白名单)。admin 只读。
func (m *Module) handleRedisConfig(w http.ResponseWriter, r *http.Request) {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	be, ctx, cancel, err := m.redisOpen(r)
	if err != nil {
		log.Printf("database: redis connect failed: %v", err)
		http.Error(w, "redis connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	cfg := make(map[string]string, len(redisConfigKeys))
	for _, k := range redisConfigKeys {
		got, gerr := be.configGet(ctx, k)
		if gerr != nil {
			log.Printf("database: redis config get %s failed: %v", k, gerr)
			http.Error(w, "redis operation failed", http.StatusBadGateway)
			return
		}
		if v, ok := got[k]; ok {
			cfg[k] = v
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg})
}

// handleRedisDetails 返回连接数/内存等详情(解析 INFO clients + memory 段)。admin 只读。
func (m *Module) handleRedisDetails(w http.ResponseWriter, r *http.Request) {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	be, ctx, cancel, err := m.redisOpen(r)
	if err != nil {
		log.Printf("database: redis connect failed: %v", err)
		http.Error(w, "redis connection failed", http.StatusBadGateway)
		return
	}
	defer cancel()
	defer be.close()
	clients, err := be.infoSection(ctx, "clients")
	if err != nil {
		log.Printf("database: redis info clients failed: %v", err)
		http.Error(w, "redis operation failed", http.StatusBadGateway)
		return
	}
	memory, err := be.infoSection(ctx, "memory")
	if err != nil {
		log.Printf("database: redis info memory failed: %v", err)
		http.Error(w, "redis operation failed", http.StatusBadGateway)
		return
	}
	details := map[string]string{}
	pickInfoFields(clients, details, "connected_clients", "blocked_clients", "maxclients")
	pickInfoFields(memory, details, "used_memory", "used_memory_human", "used_memory_peak",
		"used_memory_peak_human", "maxmemory", "maxmemory_human", "mem_fragmentation_ratio")
	writeJSON(w, http.StatusOK, map[string]any{"details": details})
}

// pickInfoFields 从 redis INFO 文本(key:value 行)中提取指定字段填入 dst。
func pickInfoFields(info string, dst map[string]string, keys ...string) {
	want := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		want[k] = struct{}{}
	}
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, want := want[k]; want {
			dst[k] = v
		}
	}
}
