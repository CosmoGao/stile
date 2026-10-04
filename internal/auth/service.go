package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/CosmoGao/stile/internal/identity"
)

var (
	ErrBadCredentials = errors.New("bad credentials")
	ErrLocked         = errors.New("locked")
	ErrDisabled       = errors.New("disabled")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrBadPassword    = errors.New("bad password")
	ErrTOTPAlready    = errors.New("totp already enabled")
	ErrTOTPCode       = errors.New("bad totp code")
	ErrNoTOTP         = errors.New("totp not pending")
)

type Service struct {
	db              *sql.DB
	key             []byte
	sessionTTL      time.Duration
	lockoutFailures int
	lockoutDuration time.Duration
	now             func() time.Time
}

func New(db *sql.DB, key []byte, sessionTTL time.Duration, lockoutFailures int, lockoutDuration time.Duration, now func() time.Time) *Service {
	k := make([]byte, len(key))
	copy(k, key)
	if now == nil {
		now = time.Now
	}
	return &Service{
		db:              db,
		key:             k,
		sessionTTL:      sessionTTL,
		lockoutFailures: lockoutFailures,
		lockoutDuration: lockoutDuration,
		now:             now,
	}
}

func (s *Service) CreateFirstAdmin(ctx context.Context, username, password string) ([]byte, identity.User, error) {
	if !identity.ValidUsername(username) {
		return nil, identity.User{}, identity.ErrBadUsername
	}
	if password == "" || len(password) > 1024 {
		return nil, identity.User{}, ErrBadPassword
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, identity.User{}, err
	}
	now := s.now()
	u, err := identity.CreateFirstAdmin(ctx, s.db, username, hash, now)
	if err != nil {
		return nil, identity.User{}, err
	}
	raw, err := s.issue(ctx, u.ID, now)
	if err != nil {
		return nil, identity.User{}, err
	}
	return raw, u, nil
}

func (s *Service) CreateUser(ctx context.Context, username, password string) error {
	if !identity.ValidUsername(username) {
		return identity.ErrBadUsername
	}
	if password == "" || len(password) > 1024 {
		return ErrBadPassword
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return identity.InsertUser(ctx, s.db, username, hash, identity.RoleUser, s.now())
}

func (s *Service) Login(ctx context.Context, username, password, code string) ([]byte, identity.User, error) {
	now := s.now()
	u, err := identity.GetByUsername(ctx, s.db, username)
	if errors.Is(err, identity.ErrNotFound) {
		verifyUnknown(password)
		return nil, identity.User{}, ErrBadCredentials
	}
	if err != nil {
		return nil, identity.User{}, err
	}
	if u.LockedUntil != nil && !now.Before(*u.LockedUntil) {
		if err := identity.ClearFailures(ctx, s.db, u.ID, now); err != nil {
			return nil, identity.User{}, err
		}
		u.FailedAttempts = 0
		u.LockedUntil = nil
	}
	if u.Locked(now) {
		verifyPassword(u.PasswordHash, password)
		return nil, identity.User{}, ErrLocked
	}
	if !verifyPassword(u.PasswordHash, password) {
		return nil, identity.User{}, s.fail(ctx, u.ID, now)
	}
	if u.TOTPEnabled {
		secret, err := s.totpSecret(u)
		if err != nil {
			return nil, identity.User{}, err
		}
		if !validateCode(secret, code, now) {
			return nil, identity.User{}, s.fail(ctx, u.ID, now)
		}
	}
	if u.Disabled {
		return nil, identity.User{}, ErrDisabled
	}
	raw, err := s.issue(ctx, u.ID, now)
	if err != nil {
		return nil, identity.User{}, err
	}
	return raw, u, nil
}

func (s *Service) fail(ctx context.Context, userID string, now time.Time) error {
	locked, err := s.noteFailure(ctx, userID, now)
	if err != nil {
		return err
	}
	if locked {
		return ErrLocked
	}
	return ErrBadCredentials
}

func (s *Service) noteFailure(ctx context.Context, userID string, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET failed_attempts = failed_attempts + 1, updated_at = ? WHERE id = ?`, identity.FormatTime(now), userID); err != nil {
		return false, err
	}
	var attempts int
	if err := tx.QueryRowContext(ctx, `SELECT failed_attempts FROM users WHERE id = ?`, userID).Scan(&attempts); err != nil {
		return false, err
	}
	locked := false
	if attempts >= s.lockoutFailures {
		until := now.Add(s.lockoutDuration)
		if _, err := tx.ExecContext(ctx, `UPDATE users SET locked_until = ? WHERE id = ?`, identity.FormatTime(until), userID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM login_tokens WHERE user_id = ?`, userID); err != nil {
			return false, err
		}
		locked = true
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return locked, nil
}

func (s *Service) issue(ctx context.Context, userID string, now time.Time) ([]byte, error) {
	raw, err := randomToken()
	if err != nil {
		return nil, err
	}
	id, err := identity.NewID()
	if err != nil {
		return nil, err
	}
	exp := now.Add(s.sessionTTL)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	u, err := identity.GetByID(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrDisabled
	}
	if u.Locked(now) {
		return nil, ErrLocked
	}
	if err := identity.ClearFailures(ctx, tx, userID, now); err != nil {
		return nil, err
	}
	if err := insertToken(ctx, tx, id, userID, tokenHash(raw), exp, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *Service) Logout(ctx context.Context, raw []byte) error {
	if len(raw) != 32 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_tokens WHERE token_hash = ?`, tokenHash(raw))
	return err
}

func (s *Service) UserByToken(ctx context.Context, raw []byte) (identity.User, error) {
	if len(raw) != 32 {
		return identity.User{}, ErrUnauthorized
	}
	now := s.now()
	var userID, expText string
	err := s.db.QueryRowContext(ctx, `SELECT user_id, expires_at FROM login_tokens WHERE token_hash = ?`, tokenHash(raw)).Scan(&userID, &expText)
	if errors.Is(err, sql.ErrNoRows) {
		return identity.User{}, ErrUnauthorized
	}
	if err != nil {
		return identity.User{}, err
	}
	exp, err := identity.ParseTime(expText)
	if err != nil {
		return identity.User{}, err
	}
	if !now.Before(exp) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM login_tokens WHERE token_hash = ?`, tokenHash(raw))
		return identity.User{}, ErrUnauthorized
	}
	u, err := identity.GetByID(ctx, s.db, userID)
	if err != nil {
		return identity.User{}, ErrUnauthorized
	}
	if u.Disabled || u.Locked(now) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM login_tokens WHERE user_id = ?`, u.ID)
		return identity.User{}, ErrUnauthorized
	}
	return u, nil
}

func (s *Service) DisableUser(ctx context.Context, id string) error {
	if _, err := identity.GetByID(ctx, s.db, id); err != nil {
		return err
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled = 1, updated_at = ? WHERE id = ?`, identity.FormatTime(now), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_tokens WHERE user_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) ClearLock(ctx context.Context, id string) error {
	if _, err := identity.GetByID(ctx, s.db, id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`, identity.FormatTime(s.now()), id)
	return err
}

func (s *Service) ClearTOTP(ctx context.Context, id string) error {
	if _, err := identity.GetByID(ctx, s.db, id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_enabled = 0, totp_secret_nonce = NULL, totp_secret_ciphertext = NULL, updated_at = ? WHERE id = ?`, identity.FormatTime(s.now()), id)
	return err
}

func (s *Service) BeginTOTP(ctx context.Context, userID string) (string, string, error) {
	u, err := identity.GetByID(ctx, s.db, userID)
	if err != nil {
		return "", "", err
	}
	if u.TOTPEnabled {
		return "", "", ErrTOTPAlready
	}
	secret, err := newTOTPSecret(u.Username)
	if err != nil {
		return "", "", err
	}
	nonce, ct, err := seal(s.key, []byte(u.ID), []byte(secret))
	if err != nil {
		return "", "", err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_enabled = 0, totp_secret_nonce = ?, totp_secret_ciphertext = ?, updated_at = ? WHERE id = ? AND totp_enabled = 0`, nonce, ct, identity.FormatTime(s.now()), u.ID)
	if err != nil {
		return "", "", err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", "", err
	}
	if n == 0 {
		return "", "", ErrTOTPAlready
	}
	return secret, otpauthURI(u.Username, secret), nil
}

func (s *Service) ConfirmTOTP(ctx context.Context, userID, code string) error {
	u, err := identity.GetByID(ctx, s.db, userID)
	if err != nil {
		return err
	}
	if u.TOTPEnabled {
		return ErrTOTPAlready
	}
	if len(u.TOTPNonce) == 0 || len(u.TOTPCiphertext) == 0 {
		return ErrNoTOTP
	}
	plain, err := open(s.key, []byte(u.ID), u.TOTPNonce, u.TOTPCiphertext)
	if err != nil {
		return err
	}
	if !validateCode(string(plain), code, s.now()) {
		return ErrTOTPCode
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_enabled = 1, updated_at = ? WHERE id = ? AND totp_enabled = 0 AND totp_secret_ciphertext IS NOT NULL`, identity.FormatTime(s.now()), u.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoTOTP
	}
	return nil
}

func (s *Service) CancelTOTP(ctx context.Context, userID string) error {
	u, err := identity.GetByID(ctx, s.db, userID)
	if err != nil {
		return err
	}
	if u.TOTPEnabled {
		return ErrTOTPAlready
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET totp_secret_nonce = NULL, totp_secret_ciphertext = NULL, updated_at = ? WHERE id = ? AND totp_enabled = 0`, identity.FormatTime(s.now()), u.ID)
	return err
}

func (s *Service) totpSecret(u identity.User) (string, error) {
	plain, err := open(s.key, []byte(u.ID), u.TOTPNonce, u.TOTPCiphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func randomToken() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func tokenHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func insertToken(ctx context.Context, tx *sql.Tx, id, userID, hash string, exp, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO login_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, userID, hash, identity.FormatTime(exp), identity.FormatTime(now))
	return err
}
