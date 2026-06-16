package sites

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// handleCreateBackup 把站点目录打成 tar.gz 存到 BackupDir,记录元数据。需 operator+。
func (m *Module) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	if site.RootDir == "" {
		http.Error(w, "site has no directory to back up", http.StatusConflict)
		return
	}
	set, ok := m.loadSettings(w)
	if !ok {
		return
	}
	filename := fmt.Sprintf("%s-%d.tar.gz", site.Name, time.Now().Unix())
	destPath, err := backupPath(set, filename)
	if err != nil {
		log.Printf("sites: backup path %q: %v", filename, err)
		http.Error(w, "backup failed", http.StatusInternalServerError)
		return
	}
	size, err := m.archiver.Pack(site.RootDir, destPath)
	if err != nil {
		log.Printf("sites: backup pack %q failed: %v", site.Name, err)
		_ = m.archiver.Remove(destPath)
		http.Error(w, "backup failed", http.StatusInternalServerError)
		return
	}
	b := Backup{SiteID: site.ID, Filename: filename, Size: size, CreatedBy: &uid}
	id, err := m.ss.createBackup(b)
	if err != nil {
		log.Printf("sites: backup persist failed: %v", err)
		_ = m.archiver.Remove(destPath)
		http.Error(w, "backup failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "sites.backup.create", site.Name+" "+filename, m.clientIP(r))
	created, _ := m.ss.getBackup(id)
	writeJSON(w, http.StatusCreated, created)
}

// handleListBackups 列出站点的全部备份(新到旧)。
func (m *Module) handleListBackups(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	backups, err := m.ss.listBackups(site.ID)
	if err != nil {
		log.Printf("sites: list backups failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if backups == nil {
		backups = []Backup{}
	}
	writeJSON(w, http.StatusOK, backups)
}

// handleDownloadBackup 流式下载归档。
func (m *Module) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	b, set, ok := m.loadBackup(w, r, site)
	if !ok {
		return
	}
	path, err := backupPath(set, b.Filename)
	if err != nil {
		http.Error(w, "backup not found", http.StatusNotFound)
		return
	}
	rc, err := m.archiver.Open(path)
	if err != nil {
		http.Error(w, "backup not found", http.StatusNotFound)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+b.Filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

// loadBackup 解析 {bid}、取备份并校验归属于路径站点(否则 404),同时返回设置。
func (m *Module) loadBackup(w http.ResponseWriter, r *http.Request, site Site) (Backup, Settings, bool) {
	bid, ok := parseParamID(w, r, "bid")
	if !ok {
		return Backup{}, Settings{}, false
	}
	b, err := m.ss.getBackup(bid)
	if err != nil || b.SiteID != site.ID {
		http.Error(w, "backup not found", http.StatusNotFound)
		return Backup{}, Settings{}, false
	}
	set, ok := m.loadSettings(w)
	if !ok {
		return Backup{}, Settings{}, false
	}
	return b, set, true
}

func parseParamID(w http.ResponseWriter, r *http.Request, key string) (int64, bool) {
	raw := chi.URLParamFromCtx(r.Context(), key)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}
