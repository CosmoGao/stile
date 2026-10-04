package identity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrSetupClosed = errors.New("setup closed")
	ErrBadUsername = errors.New("bad username")
	ErrDuplicate   = errors.New("duplicate username")
)

type DBTX interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type User struct {
	ID             string
	Username       string
	PasswordHash   string
	Role           string
	TOTPEnabled    bool
	TOTPNonce      []byte
	TOTPCiphertext []byte
	FailedAttempts int
	LockedUntil    *time.Time
	Disabled       bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (u User) Locked(now time.Time) bool {
	return u.LockedUntil != nil && now.Before(*u.LockedUntil)
}

func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func ParseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

func ValidUsername(s string) bool {
	if s == "" || s != strings.TrimSpace(s) {
		return false
	}
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
		n++
	}
	return n >= 1 && n <= 64
}

func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

const userSelect = `SELECT id, username, password_hash, role, totp_enabled, totp_secret_nonce, totp_secret_ciphertext, failed_attempts, locked_until, disabled, created_at, updated_at FROM users`

func Count(ctx context.Context, db DBTX) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func GetByUsername(ctx context.Context, db DBTX, username string) (User, error) {
	return one(ctx, db, userSelect+` WHERE username = ?`, username)
}

func GetByID(ctx context.Context, db DBTX, id string) (User, error) {
	return one(ctx, db, userSelect+` WHERE id = ?`, id)
}

func List(ctx context.Context, db DBTX) ([]User, error) {
	rows, err := db.QueryContext(ctx, userSelect+` ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func InsertUser(ctx context.Context, db DBTX, username, passwordHash, role string, now time.Time) error {
	if role != RoleAdmin && role != RoleUser {
		return fmt.Errorf("invalid role")
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	ts := FormatTime(now)
	_, err = db.ExecContext(ctx, `INSERT INTO users (
		id, username, password_hash, role, totp_enabled, failed_attempts, disabled, created_at, updated_at
	) VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?)`, id, username, passwordHash, role, ts, ts)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

func CreateFirstAdmin(ctx context.Context, db *sql.DB, username, passwordHash string, now time.Time) (User, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return User{}, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return User{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return User{}, err
	}
	if n != 0 {
		return User{}, ErrSetupClosed
	}
	id, err := NewID()
	if err != nil {
		return User{}, err
	}
	ts := FormatTime(now)
	if _, err := conn.ExecContext(ctx, `INSERT INTO users (
		id, username, password_hash, role, totp_enabled, failed_attempts, disabled, created_at, updated_at
	) VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?)`, id, username, passwordHash, RoleAdmin, ts, ts); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ErrDuplicate
		}
		return User{}, err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return User{}, err
	}
	committed = true
	now = now.UTC()
	return User{
		ID:           id,
		Username:     username,
		PasswordHash: passwordHash,
		Role:         RoleAdmin,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func ClearFailures(ctx context.Context, db DBTX, id string, now time.Time) error {
	_, err := db.ExecContext(ctx, `UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`, FormatTime(now), id)
	return err
}

func one(ctx context.Context, db DBTX, query, arg string) (User, error) {
	u, err := scanUser(db.QueryRowContext(ctx, query, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(s scanner) (User, error) {
	var u User
	var totpEnabled, disabled int
	var locked sql.NullString
	var created, updated string
	err := s.Scan(
		&u.ID,
		&u.Username,
		&u.PasswordHash,
		&u.Role,
		&totpEnabled,
		&u.TOTPNonce,
		&u.TOTPCiphertext,
		&u.FailedAttempts,
		&locked,
		&disabled,
		&created,
		&updated,
	)
	if err != nil {
		return User{}, err
	}
	u.TOTPEnabled = totpEnabled != 0
	u.Disabled = disabled != 0
	if locked.Valid {
		t, err := ParseTime(locked.String)
		if err != nil {
			return User{}, err
		}
		u.LockedUntil = &t
	}
	u.CreatedAt, err = ParseTime(created)
	if err != nil {
		return User{}, err
	}
	u.UpdatedAt, err = ParseTime(updated)
	if err != nil {
		return User{}, err
	}
	return u, nil
}
