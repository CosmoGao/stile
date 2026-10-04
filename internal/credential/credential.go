package credential

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/CosmoGao/stile/internal/identity"
	"golang.org/x/crypto/ssh"
)

const (
	KindPassword   = "password"
	KindPrivateKey = "ssh_private_key"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrBadInput           = errors.New("bad input")
	ErrBadKey             = errors.New("bad private key")
	ErrPassphraseRequired = errors.New("passphrase required")
	ErrBadPassphrase      = errors.New("bad passphrase")
	ErrInUse              = errors.New("credential in use")
)

// Credential is the public record. It has no secret, nonce, or ciphertext.
type Credential struct {
	ID          string
	Name        string
	Kind        string
	LoginName   string
	Fingerprint string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Input is a create or replace submission.
// KeyPassphrase is used only while unwrapping an encrypted private key.
// It is not stored. Kind is ignored by Replace; the stored kind stays.
type Input struct {
	Name          string
	Kind          string
	LoginName     string
	Secret        string
	KeyPassphrase string
}

type Service struct {
	db  *sql.DB
	key []byte
	now func() time.Time
}

func New(db *sql.DB, key []byte, now func() time.Time) *Service {
	k := make([]byte, len(key))
	copy(k, key)
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, key: k, now: now}
}

func (s *Service) List(ctx context.Context) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, kind, login_name, fingerprint, created_at, updated_at FROM credentials ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) Create(ctx context.Context, in Input) (Credential, error) {
	name, login, err := cleanNames(in.Name, in.LoginName)
	if err != nil {
		return Credential{}, err
	}
	if in.Kind != KindPassword && in.Kind != KindPrivateKey {
		return Credential{}, ErrBadInput
	}
	plain, fp, err := material(in.Kind, in.Secret, in.KeyPassphrase)
	if err != nil {
		return Credential{}, err
	}
	id, err := identity.NewID()
	if err != nil {
		return Credential{}, err
	}
	nonce, ct, err := seal(s.key, []byte(id), plain)
	if err != nil {
		return Credential{}, err
	}
	now := s.now().UTC()
	ts := identity.FormatTime(now)
	var fpVal any
	if fp != "" {
		fpVal = fp
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO credentials (
		id, name, kind, login_name, secret_nonce, secret_ciphertext, fingerprint, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, name, in.Kind, login, nonce, ct, fpVal, ts, ts)
	if err != nil {
		return Credential{}, err
	}
	return Credential{
		ID: id, Name: name, Kind: in.Kind, LoginName: login, Fingerprint: fp,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

// Replace updates the name and login name. A non-empty secret replaces the
// stored material under a new nonce. An empty secret keeps the previous
// ciphertext. The key passphrase is never written.
func (s *Service) Replace(ctx context.Context, id string, in Input) (Credential, error) {
	cur, nonce, ct, err := s.load(ctx, s.db, id)
	if err != nil {
		return Credential{}, err
	}
	name, login, err := cleanNames(in.Name, in.LoginName)
	if err != nil {
		return Credential{}, err
	}
	fp := cur.Fingerprint
	if secretProvided(cur.Kind, in.Secret) {
		plain, nextFP, err := material(cur.Kind, in.Secret, in.KeyPassphrase)
		if err != nil {
			return Credential{}, err
		}
		nonce, ct, err = seal(s.key, []byte(id), plain)
		if err != nil {
			return Credential{}, err
		}
		fp = nextFP
	}
	now := s.now().UTC()
	ts := identity.FormatTime(now)
	var fpVal any
	if fp != "" {
		fpVal = fp
	}
	res, err := s.db.ExecContext(ctx, `UPDATE credentials
		SET name = ?, login_name = ?, secret_nonce = ?, secret_ciphertext = ?, fingerprint = ?, updated_at = ?
		WHERE id = ?`, name, login, nonce, ct, fpVal, ts, id)
	if err != nil {
		return Credential{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Credential{}, err
	}
	if n == 0 {
		return Credential{}, ErrNotFound
	}
	cur.Name = name
	cur.LoginName = login
	cur.Fingerprint = fp
	cur.UpdatedAt = now
	return cur, nil
}

// Lookup returns the public credential fields. It does not decrypt the secret.
func (s *Service) Lookup(ctx context.Context, id string) (Credential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, kind, login_name, fingerprint, created_at, updated_at FROM credentials WHERE id = ?`, id)
	c, err := scanCredential(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, err
	}
	return c, nil
}

// Reveal decrypts one credential for the admin view. Callers must not log the
// plaintext. This does not write a row.
func (s *Service) Reveal(ctx context.Context, id string) (Credential, string, error) {
	cur, nonce, ct, err := s.load(ctx, s.db, id)
	if err != nil {
		return Credential{}, "", err
	}
	plain, err := open(s.key, []byte(id), nonce, ct)
	if err != nil {
		return Credential{}, "", err
	}
	return cur, string(plain), nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE credential_id = ?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrInUse
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM credentials WHERE id = ?`, id)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return ErrInUse
		}
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Service) load(ctx context.Context, q querier, id string) (Credential, []byte, []byte, error) {
	var c Credential
	var fp sql.NullString
	var created, updated string
	var nonce, ct []byte
	err := q.QueryRowContext(ctx, `SELECT id, name, kind, login_name, fingerprint, created_at, updated_at, secret_nonce, secret_ciphertext FROM credentials WHERE id = ?`, id).Scan(
		&c.ID, &c.Name, &c.Kind, &c.LoginName, &fp, &created, &updated, &nonce, &ct,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, nil, nil, ErrNotFound
	}
	if err != nil {
		return Credential{}, nil, nil, err
	}
	if fp.Valid {
		c.Fingerprint = fp.String
	}
	c.CreatedAt, err = identity.ParseTime(created)
	if err != nil {
		return Credential{}, nil, nil, err
	}
	c.UpdatedAt, err = identity.ParseTime(updated)
	if err != nil {
		return Credential{}, nil, nil, err
	}
	return c, nonce, ct, nil
}

func scanCredential(s scanner) (Credential, error) {
	var c Credential
	var fp sql.NullString
	var created, updated string
	if err := s.Scan(&c.ID, &c.Name, &c.Kind, &c.LoginName, &fp, &created, &updated); err != nil {
		return Credential{}, err
	}
	if fp.Valid {
		c.Fingerprint = fp.String
	}
	var err error
	c.CreatedAt, err = identity.ParseTime(created)
	if err != nil {
		return Credential{}, err
	}
	c.UpdatedAt, err = identity.ParseTime(updated)
	if err != nil {
		return Credential{}, err
	}
	return c, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func cleanNames(name, login string) (string, string, error) {
	name = strings.TrimSpace(name)
	login = strings.TrimSpace(login)
	if !validLabel(name, 128) || !validLabel(login, 128) {
		return "", "", ErrBadInput
	}
	return name, login, nil
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

func secretProvided(kind, secret string) bool {
	if kind == KindPrivateKey {
		return strings.TrimSpace(secret) != ""
	}
	return secret != ""
}

func material(kind, secret, passphrase string) ([]byte, string, error) {
	switch kind {
	case KindPassword:
		if secret == "" || len(secret) > 4096 || strings.IndexByte(secret, 0) >= 0 {
			return nil, "", ErrBadInput
		}
		return []byte(secret), "", nil
	case KindPrivateKey:
		return unwrapKey(secret, passphrase)
	default:
		return nil, "", ErrBadInput
	}
}

// unwrapKey decrypts a key passphrase only for this call. The returned bytes
// are the unencrypted PEM. The passphrase is not part of that PEM.
func unwrapKey(secret, passphrase string) ([]byte, string, error) {
	pemBytes := []byte(strings.TrimSpace(secret))
	if len(pemBytes) == 0 || len(pemBytes) > 256*1024 {
		return nil, "", ErrBadKey
	}
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return nil, "", ErrBadKey
		}
		if passphrase == "" {
			return nil, "", ErrPassphraseRequired
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) {
				return nil, "", ErrBadPassphrase
			}
			return nil, "", ErrBadKey
		}
	}
	pk, ok := raw.(crypto.PrivateKey)
	if !ok {
		return nil, "", ErrBadKey
	}
	signer, err := ssh.NewSignerFromKey(pk)
	if err != nil {
		return nil, "", ErrBadKey
	}
	block, err := ssh.MarshalPrivateKey(pk, "")
	if err != nil {
		return nil, "", ErrBadKey
	}
	stored := pem.EncodeToMemory(block)
	if len(stored) == 0 {
		return nil, "", ErrBadKey
	}
	return stored, ssh.FingerprintSHA256(signer.PublicKey()), nil
}

func seal(key, aad, plain []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, nil, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	if gcm.NonceSize() != 12 {
		return nil, nil, errors.New("unexpected nonce size")
	}
	nonce = make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plain, aad)
	return nonce, ciphertext, nil
}

func open(key, aad, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != 12 {
		return nil, errors.New("nonce must be 12 bytes")
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}
