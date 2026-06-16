package sites

import (
	"log"
	"net/http"
)

// handleRestoreBackup 把归档解回站点目录。危险:覆盖文件,需 admin + 二次确认。
// 仅动文件,不 reload nginx。Unpack 失败(含 Zip-Slip)→ 400。
func (m *Module) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	if site.RootDir == "" {
		http.Error(w, "site has no directory to restore into", http.StatusConflict)
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
	if err := m.archiver.Unpack(path, site.RootDir); err != nil {
		log.Printf("sites: restore %q failed: %v", site.Name, err)
		http.Error(w, "restore failed", http.StatusBadRequest)
		return
	}
	m.deps.Audit(&uid, "sites.backup.restore", site.Name+" "+b.Filename, m.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"restored": true})
}

// handleDeleteBackup 删归档文件与元数据。危险:需 admin + 二次确认。
func (m *Module) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	b, set, ok := m.loadBackup(w, r, site)
	if !ok {
		return
	}
	if path, err := backupPath(set, b.Filename); err == nil {
		_ = m.archiver.Remove(path)
	}
	if err := m.ss.deleteBackup(b.ID); err != nil {
		log.Printf("sites: delete backup persist failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "sites.backup.delete", site.Name+" "+b.Filename, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}
