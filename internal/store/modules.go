package store

// SetModuleEnabled upsert 模块启用状态。
func (s *Store) SetModuleEnabled(id string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.DB.Exec(
		`INSERT INTO module_state (id, enabled) VALUES (?, ?)
		 ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled`,
		id, v,
	)
	return err
}

// EnabledModules 返回 id->enabled 映射(只含表里有记录的)。
func (s *Store) EnabledModules() (map[string]bool, error) {
	rows, err := s.DB.Query(`SELECT id, enabled FROM module_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var id string
		var enabled int
		if err := rows.Scan(&id, &enabled); err != nil {
			return nil, err
		}
		out[id] = enabled == 1
	}
	return out, rows.Err()
}
