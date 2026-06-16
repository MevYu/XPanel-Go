package store

// BanIP upsert 一条 IP 封禁,bannedUntil 为 Unix 秒。
func (s *Store) BanIP(ip string, bannedUntil int64) error {
	_, err := s.DB.Exec(
		`INSERT INTO ip_bans (ip, banned_until) VALUES (?, ?)
		 ON CONFLICT(ip) DO UPDATE SET banned_until = excluded.banned_until`,
		ip, bannedUntil,
	)
	return err
}

// ActiveBans 返回 banned_until > now 的封禁(ip -> bannedUntil)。
func (s *Store) ActiveBans(now int64) (map[string]int64, error) {
	rows, err := s.DB.Query(`SELECT ip, banned_until FROM ip_bans WHERE banned_until > ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var ip string
		var until int64
		if err := rows.Scan(&ip, &until); err != nil {
			return nil, err
		}
		out[ip] = until
	}
	return out, rows.Err()
}

// DeleteExpiredBans 删除 banned_until <= now 的过期封禁。
func (s *Store) DeleteExpiredBans(now int64) error {
	_, err := s.DB.Exec(`DELETE FROM ip_bans WHERE banned_until <= ?`, now)
	return err
}
