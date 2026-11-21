// Package store persists users, networks, devices and share links in SQLite.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db   *sql.DB
	aead cipher.AEAD
}

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

type Network struct {
	ID         int64
	UserID     int64
	Name       string
	Slug       string
	Subnet     netip.Prefix
	MaxClients int
	CreatedAt  time.Time
}

type Device struct {
	ID           int64
	NetworkID    int64
	Name         string
	Hostname     string
	Platform     string
	IP           netip.Addr
	PublicKey    string
	PrivateKey   string // empty when the user brought their own key
	PresharedKey string
	CreatedAt    time.Time
}

type Share struct {
	ID        int64
	DeviceID  int64
	ExpiresAt time.Time
	CreatedAt time.Time
}

const schema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS networks (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  subnet TEXT NOT NULL UNIQUE,
  max_clients INTEGER NOT NULL,
  created_at TIMESTAMP NOT NULL,
  UNIQUE(user_id, slug)
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY,
  network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  hostname TEXT NOT NULL,
  platform TEXT NOT NULL,
  ip TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL UNIQUE,
  private_key_enc TEXT NOT NULL DEFAULT '',
  preshared_key_enc TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  UNIQUE(network_id, hostname)
);
CREATE TABLE IF NOT EXISTS shares (
  id INTEGER PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dns_zones (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL UNIQUE,
  network_id INTEGER UNIQUE REFERENCES networks(id) ON DELETE CASCADE,
  api_user TEXT NOT NULL UNIQUE,
  api_key_enc TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS dns_records (
  id INTEGER PRIMARY KEY,
  zone_id INTEGER NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  ip TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  UNIQUE(zone_id, name)
);
CREATE TABLE IF NOT EXISTS dns_txt (
  id INTEGER PRIMARY KEY,
  zone_id INTEGER NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
  value TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL
);
`

// Open opens (and migrates) the database. secret is used to derive the key
// that encrypts WireGuard private and preshared keys at rest.
func Open(path, secret string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	k := sha256.Sum256([]byte("privnet-at-rest:" + secret))
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, aead: aead}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) encrypt(plain string) string {
	if plain == "" {
		return ""
	}
	nonce := make([]byte, s.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, []byte(plain), nil))
}

func (s *Store) decrypt(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	p, err := s.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt (wrong APP_SECRET?): %w", err)
	}
	return string(p), nil
}

// HashToken returns the stored representation of a bearer token.
func HashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ---- settings ----

func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) SecretSetting(ctx context.Context, key string) (string, error) {
	v, err := s.Setting(ctx, key)
	if err != nil {
		return "", err
	}
	return s.decrypt(v)
}

func (s *Store) SetSecretSetting(ctx context.Context, key, value string) error {
	return s.SetSetting(ctx, key, s.encrypt(value))
}

// ---- users & sessions ----

func (s *Store) CreateUser(ctx context.Context, email, hash string) (*User, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)`, email, hash, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Email: email, PasswordHash: hash, CreatedAt: now}, nil
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx, `SELECT id,email,password_hash,created_at FROM users WHERE email=?`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) CreateSession(ctx context.Context, token string, userID int64, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)`,
		HashToken(token), userID, time.Now().UTC().Add(ttl))
	return err
}

func (s *Store) UserBySession(ctx context.Context, token string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.email,u.password_hash,u.created_at FROM sessions s
		JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at > ?`, HashToken(token), time.Now().UTC()).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, HashToken(token))
	return err
}

func (s *Store) PurgeExpired(ctx context.Context) error {
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM shares WHERE expires_at <= ?`, now)
	return err
}

// ---- networks ----

const netCols = `id,user_id,name,slug,subnet,max_clients,created_at`

func scanNetwork(sc interface{ Scan(...any) error }) (*Network, error) {
	n := &Network{}
	var subnet string
	if err := sc.Scan(&n.ID, &n.UserID, &n.Name, &n.Slug, &subnet, &n.MaxClients, &n.CreatedAt); err != nil {
		return nil, err
	}
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return nil, err
	}
	n.Subnet = p
	return n, nil
}

func (s *Store) CreateNetwork(ctx context.Context, n *Network) error {
	n.CreatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO networks(user_id,name,slug,subnet,max_clients,created_at) VALUES(?,?,?,?,?,?)`,
		n.UserID, n.Name, n.Slug, n.Subnet.String(), n.MaxClients, n.CreatedAt)
	if err != nil {
		return err
	}
	n.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) Network(ctx context.Context, id int64) (*Network, error) {
	n, err := scanNetwork(s.db.QueryRowContext(ctx, `SELECT `+netCols+` FROM networks WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return n, err
}

func (s *Store) networks(ctx context.Context, q string, args ...any) ([]*Network, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Network
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) NetworksByUser(ctx context.Context, userID int64) ([]*Network, error) {
	return s.networks(ctx, `SELECT `+netCols+` FROM networks WHERE user_id=? ORDER BY created_at`, userID)
}

func (s *Store) AllNetworks(ctx context.Context) ([]*Network, error) {
	return s.networks(ctx, `SELECT `+netCols+` FROM networks ORDER BY id`)
}

func (s *Store) DeleteNetwork(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM networks WHERE id=?`, id)
	return err
}

// ---- devices ----

const devCols = `id,network_id,name,hostname,platform,ip,public_key,private_key_enc,preshared_key_enc,created_at`

func (s *Store) scanDevice(sc interface{ Scan(...any) error }) (*Device, error) {
	d := &Device{}
	var ip, priv, psk string
	if err := sc.Scan(&d.ID, &d.NetworkID, &d.Name, &d.Hostname, &d.Platform, &ip, &d.PublicKey, &priv, &psk, &d.CreatedAt); err != nil {
		return nil, err
	}
	var err error
	if d.IP, err = netip.ParseAddr(ip); err != nil {
		return nil, err
	}
	if d.PrivateKey, err = s.decrypt(priv); err != nil {
		return nil, err
	}
	if d.PresharedKey, err = s.decrypt(psk); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Store) CreateDevice(ctx context.Context, d *Device) error {
	d.CreatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO devices(network_id,name,hostname,platform,ip,public_key,private_key_enc,preshared_key_enc,created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, d.NetworkID, d.Name, d.Hostname, d.Platform, d.IP.String(), d.PublicKey,
		s.encrypt(d.PrivateKey), s.encrypt(d.PresharedKey), d.CreatedAt)
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) Device(ctx context.Context, id int64) (*Device, error) {
	d, err := s.scanDevice(s.db.QueryRowContext(ctx, `SELECT `+devCols+` FROM devices WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

func (s *Store) devices(ctx context.Context, q string, args ...any) ([]*Device, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := s.scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) DevicesByNetwork(ctx context.Context, networkID int64) ([]*Device, error) {
	return s.devices(ctx, `SELECT `+devCols+` FROM devices WHERE network_id=? ORDER BY ip`, networkID)
}

func (s *Store) AllDevices(ctx context.Context) ([]*Device, error) {
	return s.devices(ctx, `SELECT `+devCols+` FROM devices ORDER BY id`)
}

func (s *Store) DeleteDevice(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id=?`, id)
	return err
}

// ---- shares ----

func (s *Store) CreateShare(ctx context.Context, token string, deviceID int64, ttl time.Duration) (*Share, error) {
	now := time.Now().UTC()
	sh := &Share{DeviceID: deviceID, ExpiresAt: now.Add(ttl), CreatedAt: now}
	res, err := s.db.ExecContext(ctx, `INSERT INTO shares(token_hash,device_id,expires_at,created_at) VALUES(?,?,?,?)`,
		HashToken(token), deviceID, sh.ExpiresAt, now)
	if err != nil {
		return nil, err
	}
	sh.ID, _ = res.LastInsertId()
	return sh, nil
}

func (s *Store) ShareByToken(ctx context.Context, token string) (*Share, error) {
	sh := &Share{}
	err := s.db.QueryRowContext(ctx, `SELECT id,device_id,expires_at,created_at FROM shares WHERE token_hash=? AND expires_at > ?`,
		HashToken(token), time.Now().UTC()).Scan(&sh.ID, &sh.DeviceID, &sh.ExpiresAt, &sh.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sh, err
}

func (s *Store) SharesByDevice(ctx context.Context, deviceID int64) ([]*Share, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,device_id,expires_at,created_at FROM shares WHERE device_id=? AND expires_at > ? ORDER BY created_at DESC`,
		deviceID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Share
	for rows.Next() {
		sh := &Share{}
		if err := rows.Scan(&sh.ID, &sh.DeviceID, &sh.ExpiresAt, &sh.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sh)
	}
	return out, rows.Err()
}

func (s *Store) DeleteShare(ctx context.Context, id, deviceID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM shares WHERE id=? AND device_id=?`, id, deviceID)
	return err
}
