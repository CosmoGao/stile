package asset

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/CosmoGao/stile/internal/identity"
)

const (
	ProtocolSSH    = "ssh"
	ProtocolRDP    = "rdp"
	DefaultSSHPort = 22
	DefaultRDPPort = 3389
)

var (
	ErrNotFound          = errors.New("not found")
	ErrBadInput          = errors.New("bad input")
	ErrCredentialMissing = errors.New("credential missing")
)

// Asset is the admin record. It points at a credential by id and holds no
// password, private key, or nonce.
type Asset struct {
	ID                 string
	Name               string
	Protocol           string
	Host               string
	Port               int
	CredentialID       string
	CredentialName     string
	HostKeyFingerprint string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// UserAsset is what a non-admin may be shown. It has no credential id.
// This segment does not list assets to non-admins, because nothing is granted yet.
type UserAsset struct {
	ID       string
	Name     string
	Protocol string
	Host     string
	Port     int
}

func (a Asset) ForUser() UserAsset {
	return UserAsset{
		ID:       a.ID,
		Name:     a.Name,
		Protocol: a.Protocol,
		Host:     a.Host,
		Port:     a.Port,
	}
}

type Input struct {
	Name               string
	Protocol           string
	Host               string
	Port               string
	CredentialID       string
	HostKeyFingerprint string
}

type Service struct {
	db  *sql.DB
	now func() time.Time
}

func New(db *sql.DB, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, now: now}
}

func (s *Service) List(ctx context.Context) ([]Asset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.id, a.name, a.protocol, a.host, a.port, a.credential_id, c.name, a.ssh_host_key_fingerprint, a.created_at, a.updated_at
		FROM assets a LEFT JOIN credentials c ON c.id = a.credential_id
		ORDER BY a.name, a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) Create(ctx context.Context, in Input) (Asset, error) {
	fields, err := s.normalize(ctx, in)
	if err != nil {
		return Asset{}, err
	}
	id, err := identity.NewID()
	if err != nil {
		return Asset{}, err
	}
	now := s.now().UTC()
	ts := identity.FormatTime(now)
	_, err = s.db.ExecContext(ctx, `INSERT INTO assets (
		id, name, protocol, host, port, credential_id, ssh_host_key_fingerprint, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, fields.name, fields.protocol, fields.host, fields.port, nullIfEmpty(fields.credentialID), nullIfEmpty(fields.hostKey), ts, ts)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return Asset{}, ErrCredentialMissing
		}
		return Asset{}, err
	}
	fields.id = id
	fields.created = now
	fields.updated = now
	return fields.asset(), nil
}

func (s *Service) Update(ctx context.Context, id string, in Input) (Asset, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE id = ?`, id).Scan(&n); err != nil {
		return Asset{}, err
	}
	if n == 0 {
		return Asset{}, ErrNotFound
	}
	fields, err := s.normalize(ctx, in)
	if err != nil {
		return Asset{}, err
	}
	now := s.now().UTC()
	ts := identity.FormatTime(now)
	res, err := s.db.ExecContext(ctx, `UPDATE assets SET
		name = ?, protocol = ?, host = ?, port = ?, credential_id = ?, ssh_host_key_fingerprint = ?, updated_at = ?
		WHERE id = ?`,
		fields.name, fields.protocol, fields.host, fields.port, nullIfEmpty(fields.credentialID), nullIfEmpty(fields.hostKey), ts, id)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return Asset{}, ErrCredentialMissing
		}
		return Asset{}, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return Asset{}, err
	}
	if affected == 0 {
		return Asset{}, ErrNotFound
	}
	name, err := s.credentialName(ctx, fields.credentialID)
	if err != nil {
		return Asset{}, err
	}
	fields.id = id
	fields.credentialName = name
	fields.updated = now
	var created string
	if err := s.db.QueryRowContext(ctx, `SELECT created_at FROM assets WHERE id = ?`, id).Scan(&created); err != nil {
		return Asset{}, err
	}
	fields.created, err = identity.ParseTime(created)
	if err != nil {
		return Asset{}, err
	}
	return fields.asset(), nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type fields struct {
	id             string
	name           string
	protocol       string
	host           string
	port           int
	credentialID   string
	credentialName string
	hostKey        string
	created        time.Time
	updated        time.Time
}

func (f fields) asset() Asset {
	return Asset{
		ID:                 f.id,
		Name:               f.name,
		Protocol:           f.protocol,
		Host:               f.host,
		Port:               f.port,
		CredentialID:       f.credentialID,
		CredentialName:     f.credentialName,
		HostKeyFingerprint: f.hostKey,
		CreatedAt:          f.created,
		UpdatedAt:          f.updated,
	}
}

func (s *Service) normalize(ctx context.Context, in Input) (fields, error) {
	var f fields
	f.name = strings.TrimSpace(in.Name)
	f.protocol = strings.TrimSpace(in.Protocol)
	f.host = strings.TrimSpace(in.Host)
	f.credentialID = strings.TrimSpace(in.CredentialID)
	if !validLabel(f.name, 128) || (f.protocol != ProtocolSSH && f.protocol != ProtocolRDP) || !validHost(f.host) {
		return fields{}, ErrBadInput
	}
	port, err := ResolvePort(f.protocol, in.Port)
	if err != nil {
		return fields{}, err
	}
	f.port = port
	// RDP ignores a host key fingerprint. SSH stores only what was typed.
	// Nothing here connects to the host or runs a key exchange.
	if f.protocol == ProtocolSSH {
		fp := strings.TrimSpace(in.HostKeyFingerprint)
		if fp != "" && !validLabel(fp, 256) {
			return fields{}, ErrBadInput
		}
		f.hostKey = fp
	}
	if f.credentialID != "" {
		name, err := s.credentialName(ctx, f.credentialID)
		if err != nil {
			return fields{}, err
		}
		if name == "" && !s.credentialExists(ctx, f.credentialID) {
			return fields{}, ErrCredentialMissing
		}
		f.credentialName = name
	}
	return f, nil
}

func (s *Service) credentialExists(ctx context.Context, id string) bool {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM credentials WHERE id = ?`, id).Scan(&n)
	return err == nil && n == 1
}

func (s *Service) credentialName(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", nil
	}
	var name string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM credentials WHERE id = ?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return name, nil
}

func ResolvePort(protocol, raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if protocol == ProtocolSSH {
			return DefaultSSHPort, nil
		}
		if protocol == ProtocolRDP {
			return DefaultRDPPort, nil
		}
		return 0, ErrBadInput
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, ErrBadInput
	}
	return n, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func validLabel(s string, max int) bool {
	if s == "" {
		return false
	}
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
		n++
	}
	return n <= max
}

func validHost(s string) bool {
	if !validLabel(s, 253) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAsset(s scanner) (Asset, error) {
	var a Asset
	var credID, credName, fp sql.NullString
	var created, updated string
	if err := s.Scan(&a.ID, &a.Name, &a.Protocol, &a.Host, &a.Port, &credID, &credName, &fp, &created, &updated); err != nil {
		return Asset{}, err
	}
	if credID.Valid {
		a.CredentialID = credID.String
	}
	if credName.Valid {
		a.CredentialName = credName.String
	}
	if fp.Valid {
		a.HostKeyFingerprint = fp.String
	}
	var err error
	a.CreatedAt, err = identity.ParseTime(created)
	if err != nil {
		return Asset{}, err
	}
	a.UpdatedAt, err = identity.ParseTime(updated)
	if err != nil {
		return Asset{}, err
	}
	return a, nil
}
