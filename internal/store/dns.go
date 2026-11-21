package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"
)

// MaxTXTPerZone is how many recent ACME challenge values a zone keeps. A
// wildcard+apex order needs two at once; a few more allow multi-name orders.
const MaxTXTPerZone = 5

// TXTMaxAge drops stale challenge values.
const TXTMaxAge = 24 * time.Hour

// DNSZone is a namespace <label>.<DNS_ZONE> owned by one user. Zones linked to a
// privnet network also resolve that network's device names.
type DNSZone struct {
	ID        int64
	UserID    int64
	Label     string
	NetworkID int64 // 0 for standalone zones
	APIUser   string
	APIKey    string
	CreatedAt time.Time
}

type DNSRecord struct {
	ID        int64
	ZoneID    int64
	Name      string
	IP        netip.Addr
	CreatedAt time.Time
}

type DNSTXT struct {
	ZoneID    int64
	Value     string
	CreatedAt time.Time
}

const zoneCols = `id,user_id,label,COALESCE(network_id,0),api_user,api_key_enc,created_at`

func (s *Store) scanZone(sc interface{ Scan(...any) error }) (*DNSZone, error) {
	z := &DNSZone{}
	var enc string
	if err := sc.Scan(&z.ID, &z.UserID, &z.Label, &z.NetworkID, &z.APIUser, &enc, &z.CreatedAt); err != nil {
		return nil, err
	}
	var err error
	z.APIKey, err = s.decrypt(enc)
	return z, err
}

func (s *Store) CreateDNSZone(ctx context.Context, z *DNSZone) error {
	z.CreatedAt = time.Now().UTC()
	var netID any
	if z.NetworkID != 0 {
		netID = z.NetworkID
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO dns_zones(user_id,label,network_id,api_user,api_key_enc,created_at) VALUES(?,?,?,?,?,?)`,
		z.UserID, z.Label, netID, z.APIUser, s.encrypt(z.APIKey), z.CreatedAt)
	if err != nil {
		return err
	}
	z.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) zone(ctx context.Context, where string, arg any) (*DNSZone, error) {
	z, err := s.scanZone(s.db.QueryRowContext(ctx, `SELECT `+zoneCols+` FROM dns_zones WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return z, err
}

func (s *Store) DNSZone(ctx context.Context, id int64) (*DNSZone, error) {
	return s.zone(ctx, "id=?", id)
}

func (s *Store) DNSZoneByLabel(ctx context.Context, label string) (*DNSZone, error) {
	return s.zone(ctx, "label=?", label)
}

func (s *Store) DNSZoneByAPIUser(ctx context.Context, user string) (*DNSZone, error) {
	return s.zone(ctx, "api_user=?", user)
}

func (s *Store) DNSZoneByNetwork(ctx context.Context, networkID int64) (*DNSZone, error) {
	return s.zone(ctx, "network_id=?", networkID)
}

func (s *Store) zones(ctx context.Context, q string, args ...any) ([]*DNSZone, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DNSZone
	for rows.Next() {
		z, err := s.scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

func (s *Store) DNSZonesByUser(ctx context.Context, userID int64) ([]*DNSZone, error) {
	return s.zones(ctx, `SELECT `+zoneCols+` FROM dns_zones WHERE user_id=? ORDER BY network_id IS NULL, created_at`, userID)
}

func (s *Store) AllDNSZones(ctx context.Context) ([]*DNSZone, error) {
	return s.zones(ctx, `SELECT `+zoneCols+` FROM dns_zones ORDER BY id`)
}

func (s *Store) SetDNSZoneKey(ctx context.Context, id int64, key string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE dns_zones SET api_key_enc=? WHERE id=?`, s.encrypt(key), id)
	return err
}

func (s *Store) DeleteDNSZone(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM dns_zones WHERE id=?`, id)
	return err
}

// ---- records ----

func (s *Store) CreateDNSRecord(ctx context.Context, r *DNSRecord) error {
	r.CreatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO dns_records(zone_id,name,ip,created_at) VALUES(?,?,?,?)`, r.ZoneID, r.Name, r.IP.String(), r.CreatedAt)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) records(ctx context.Context, q string, args ...any) ([]*DNSRecord, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DNSRecord
	for rows.Next() {
		r := &DNSRecord{}
		var ip string
		if err := rows.Scan(&r.ID, &r.ZoneID, &r.Name, &ip, &r.CreatedAt); err != nil {
			return nil, err
		}
		if r.IP, err = netip.ParseAddr(ip); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DNSRecordsByZone(ctx context.Context, zoneID int64) ([]*DNSRecord, error) {
	return s.records(ctx, `SELECT id,zone_id,name,ip,created_at FROM dns_records WHERE zone_id=? ORDER BY name`, zoneID)
}

func (s *Store) AllDNSRecords(ctx context.Context) ([]*DNSRecord, error) {
	return s.records(ctx, `SELECT id,zone_id,name,ip,created_at FROM dns_records`)
}

func (s *Store) DeleteDNSRecord(ctx context.Context, id, zoneID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM dns_records WHERE id=? AND zone_id=?`, id, zoneID)
	return err
}

// ---- ACME challenge TXT values ----

// AddDNSTXT stores a challenge value and trims the zone to the newest MaxTXTPerZone.
func (s *Store) AddDNSTXT(ctx context.Context, zoneID int64, value string) error {
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO dns_txt(zone_id,value,created_at) VALUES(?,?,?)`, zoneID, value, now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM dns_txt WHERE zone_id=? AND (created_at < ? OR id NOT IN
		(SELECT id FROM dns_txt WHERE zone_id=? ORDER BY id DESC LIMIT ?))`, zoneID, now.Add(-TXTMaxAge), zoneID, MaxTXTPerZone)
	return err
}

func (s *Store) AllDNSTXT(ctx context.Context) ([]DNSTXT, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT zone_id,value,created_at FROM dns_txt WHERE created_at >= ? ORDER BY id DESC`, time.Now().UTC().Add(-TXTMaxAge))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSTXT
	for rows.Next() {
		var t DNSTXT
		if err := rows.Scan(&t.ZoneID, &t.Value, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DNSTXTByZone(ctx context.Context, zoneID int64) ([]DNSTXT, error) {
	all, err := s.AllDNSTXT(ctx)
	if err != nil {
		return nil, err
	}
	var out []DNSTXT
	for _, t := range all {
		if t.ZoneID == zoneID {
			out = append(out, t)
		}
	}
	return out, nil
}
