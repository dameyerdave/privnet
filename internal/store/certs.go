package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Certificate modes.
const (
	CertDownload = "download" // name points at the device; the user installs the certificate there
	CertProxy    = "proxy"    // name points at the gateway; the hub terminates TLS and forwards to the device
)

// Certificate states.
const (
	CertPending = "pending" // first issuance queued or running
	CertIssued  = "issued"  // a valid certificate is stored (renewals keep this state)
	CertError   = "error"   // first issuance failed; LastError says why
)

// Cert is a Let's Encrypt certificate for <Name>.<network namespace>.<zone>.
type Cert struct {
	ID          int64
	DeviceID    int64
	NetworkID   int64
	Name        string // the user-chosen prefix
	Mode        string
	BackendPort int  // proxy mode: port on the device
	BackendTLS  bool // proxy mode: speak HTTPS to the device (certificate not verified)
	Status      string
	LastError   string
	KeyPEM      string // decrypted private key
	CertPEM     string // leaf + intermediates
	NotAfter    time.Time
	IssuedAt    time.Time
	AttemptedAt time.Time
	FetchToken  string // decrypted; lets the device pull renewed files without a login
	CreatedAt   time.Time
}

const certCols = `id,device_id,network_id,name,mode,backend_port,backend_tls,status,last_error,key_enc,cert_pem,not_after,issued_at,attempted_at,fetch_token_enc,created_at`

func (s *Store) scanCert(sc interface{ Scan(...any) error }) (*Cert, error) {
	c := &Cert{}
	var keyEnc, tokEnc string
	var notAfter, issued, attempted sql.NullTime
	if err := sc.Scan(&c.ID, &c.DeviceID, &c.NetworkID, &c.Name, &c.Mode, &c.BackendPort, &c.BackendTLS, &c.Status, &c.LastError,
		&keyEnc, &c.CertPEM, &notAfter, &issued, &attempted, &tokEnc, &c.CreatedAt); err != nil {
		return nil, err
	}
	c.NotAfter, c.IssuedAt, c.AttemptedAt = notAfter.Time, issued.Time, attempted.Time
	var err error
	if c.KeyPEM, err = s.decrypt(keyEnc); err != nil {
		return nil, err
	}
	c.FetchToken, err = s.decrypt(tokEnc)
	return c, err
}

func (s *Store) CreateCert(ctx context.Context, c *Cert) error {
	c.CreatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO certs(device_id,network_id,name,mode,backend_port,backend_tls,status,fetch_token_hash,fetch_token_enc,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		c.DeviceID, c.NetworkID, c.Name, c.Mode, c.BackendPort, c.BackendTLS, c.Status, HashToken(c.FetchToken), s.encrypt(c.FetchToken), c.CreatedAt)
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) cert(ctx context.Context, where string, args ...any) (*Cert, error) {
	c, err := s.scanCert(s.db.QueryRowContext(ctx, `SELECT `+certCols+` FROM certs WHERE `+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *Store) Cert(ctx context.Context, id int64) (*Cert, error) { return s.cert(ctx, `id=?`, id) }

func (s *Store) CertByFetchToken(ctx context.Context, token string) (*Cert, error) {
	return s.cert(ctx, `fetch_token_hash=?`, HashToken(token))
}

func (s *Store) certs(ctx context.Context, q string, args ...any) ([]*Cert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+certCols+` FROM certs `+q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Cert
	for rows.Next() {
		c, err := s.scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) CertsByDevice(ctx context.Context, deviceID int64) ([]*Cert, error) {
	return s.certs(ctx, `WHERE device_id=? ORDER BY name`, deviceID)
}

func (s *Store) CertsByNetwork(ctx context.Context, networkID int64) ([]*Cert, error) {
	return s.certs(ctx, `WHERE network_id=? ORDER BY name`, networkID)
}

func (s *Store) AllCerts(ctx context.Context) ([]*Cert, error) { return s.certs(ctx, `ORDER BY id`) }

// CountCertsByUser counts certificates across all networks of a user.
func (s *Store) CountCertsByUser(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM certs c JOIN networks n ON n.id=c.network_id WHERE n.user_id=?`, userID).Scan(&n)
	return n, err
}

// SaveCertIssued stores a freshly issued (or renewed) certificate.
func (s *Store) SaveCertIssued(ctx context.Context, id int64, keyPEM, certPEM string, notAfter time.Time) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE certs SET status=?, last_error='', key_enc=?, cert_pem=?, not_after=?, issued_at=?, attempted_at=? WHERE id=?`,
		CertIssued, s.encrypt(keyPEM), certPEM, notAfter.UTC(), now, now, id)
	return err
}

// SaveCertFailure records a failed attempt. A certificate that was issued
// before stays usable; one that never was moves to the error state.
func (s *Store) SaveCertFailure(ctx context.Context, id int64, msg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE certs SET last_error=?, attempted_at=?, status=CASE WHEN cert_pem='' THEN ? ELSE status END WHERE id=?`,
		msg, time.Now().UTC(), CertError, id)
	return err
}

func (s *Store) SetCertPending(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE certs SET status=?, last_error='' WHERE id=? AND cert_pem=''`, CertPending, id)
	return err
}

func (s *Store) SetCertFetchToken(ctx context.Context, id int64, token string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE certs SET fetch_token_hash=?, fetch_token_enc=? WHERE id=?`, HashToken(token), s.encrypt(token), id)
	return err
}

// DeleteCertsByNetwork removes every certificate of a network.
func (s *Store) DeleteCertsByNetwork(ctx context.Context, networkID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM certs WHERE network_id=?`, networkID)
	return err
}

func (s *Store) DeleteCert(ctx context.Context, id, deviceID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM certs WHERE id=? AND device_id=?`, id, deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
