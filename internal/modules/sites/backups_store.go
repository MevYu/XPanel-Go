package sites

import (
	"database/sql"
	"time"
)

// Backup 是一条站点备份归档的元数据。Filename 由服务端生成,从不信任客户端。
type Backup struct {
	ID        int64  `json:"id"`
	SiteID    int64  `json:"site_id"`
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	CreatedAt int64  `json:"created_at"`
	CreatedBy *int64 `json:"created_by"`
}

func (s *siteStore) createBackup(b Backup) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO site_backups (site_id, filename, size, created_by, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		b.SiteID, b.Filename, b.Size, b.CreatedBy, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *siteStore) listBackups(siteID int64) ([]Backup, error) {
	rows, err := s.db.Query(`SELECT id, site_id, filename, size, created_at, created_by
		FROM site_backups WHERE site_id = ? ORDER BY id DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Backup
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *siteStore) getBackup(id int64) (Backup, error) {
	row := s.db.QueryRow(`SELECT id, site_id, filename, size, created_at, created_by
		FROM site_backups WHERE id = ?`, id)
	return scanBackup(row)
}

func (s *siteStore) deleteBackup(id int64) error {
	_, err := s.db.Exec(`DELETE FROM site_backups WHERE id = ?`, id)
	return err
}

func scanBackup(sc scanner) (Backup, error) {
	var b Backup
	var createdBy sql.NullInt64
	if err := sc.Scan(&b.ID, &b.SiteID, &b.Filename, &b.Size, &b.CreatedAt, &createdBy); err != nil {
		return Backup{}, err
	}
	if createdBy.Valid {
		b.CreatedBy = &createdBy.Int64
	}
	return b, nil
}
