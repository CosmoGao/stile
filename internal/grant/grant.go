package grant

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/CosmoGao/stile/internal/asset"
	"github.com/CosmoGao/stile/internal/identity"
)

const (
	SubjectUser  = "user"
	SubjectGroup = "group"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("duplicate grant")
	ErrBadInput  = errors.New("bad input")
)

// Grant is one row: an asset is given to one user or one group.
// There is no permission kind. The same asset and subject keep a single row.
type Grant struct {
	ID          string
	AssetID     string
	AssetName   string
	SubjectType string
	SubjectID   string
	SubjectName string
	CreatedBy   string
	CreatedAt   time.Time
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

func (s *Service) Add(ctx context.Context, assetID, subjectType, subjectID, createdBy string) (Grant, error) {
	assetID = strings.TrimSpace(assetID)
	subjectType = strings.TrimSpace(subjectType)
	subjectID = strings.TrimSpace(subjectID)
	createdBy = strings.TrimSpace(createdBy)
	if assetID == "" || subjectID == "" || createdBy == "" || (subjectType != SubjectUser && subjectType != SubjectGroup) {
		return Grant{}, ErrBadInput
	}
	var assetName string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM assets WHERE id = ?`, assetID).Scan(&assetName)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, err
	}
	subjectName, err := s.subjectName(ctx, subjectType, subjectID)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, err
	}
	id, err := identity.NewID()
	if err != nil {
		return Grant{}, err
	}
	now := s.now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO grants (id, asset_id, subject_type, subject_id, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, assetID, subjectType, subjectID, createdBy, identity.FormatTime(now))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Grant{}, ErrDuplicate
		}
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return Grant{}, ErrNotFound
		}
		return Grant{}, err
	}
	return Grant{
		ID:          id,
		AssetID:     assetID,
		AssetName:   assetName,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		SubjectName: subjectName,
		CreatedBy:   createdBy,
		CreatedAt:   now,
	}, nil
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE id = ?`, id)
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

func (s *Service) List(ctx context.Context) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.id, g.asset_id, a.name, g.subject_type, g.subject_id,
		CASE g.subject_type WHEN 'user' THEN u.username ELSE ug.name END,
		g.created_by, g.created_at
		FROM grants g
		JOIN assets a ON a.id = g.asset_id
		LEFT JOIN users u ON g.subject_type = 'user' AND u.id = g.subject_id
		LEFT JOIN user_groups ug ON g.subject_type = 'group' AND ug.id = g.subject_id
		ORDER BY a.name, g.subject_type, g.subject_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListForUser returns the union of assets granted directly to the user and
// assets granted to any group the user belongs to. It does not read every
// asset and then hide some, and it does not select credential_id.
// Administrators are not a special case here: the management list is separate,
// and opening still uses Allowed.
func (s *Service) ListForUser(ctx context.Context, userID string) ([]asset.UserAsset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.id, a.name, a.protocol, a.host, a.port
		FROM assets a
		WHERE EXISTS (
			SELECT 1 FROM grants g
			WHERE g.asset_id = a.id AND g.subject_type = 'user' AND g.subject_id = ?
		) OR EXISTS (
			SELECT 1 FROM grants g
			INNER JOIN group_members m ON m.group_id = g.subject_id
			WHERE g.asset_id = a.id AND g.subject_type = 'group' AND m.user_id = ?
		)
		ORDER BY a.name, a.id`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []asset.UserAsset
	for rows.Next() {
		var a asset.UserAsset
		if err := rows.Scan(&a.ID, &a.Name, &a.Protocol, &a.Host, &a.Port); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Allowed reports whether the asset is in this identity's grant union.
// Role is not consulted. An administrator does not skip this check.
func (s *Service) Allowed(ctx context.Context, userID, assetID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM grants g
		WHERE g.asset_id = ?
		AND (
			(g.subject_type = 'user' AND g.subject_id = ?)
			OR (
				g.subject_type = 'group' AND EXISTS (
					SELECT 1 FROM group_members m
					WHERE m.group_id = g.subject_id AND m.user_id = ?
				)
			)
		)`, assetID, userID, userID).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Service) subjectName(ctx context.Context, subjectType, subjectID string) (string, error) {
	var name string
	var err error
	switch subjectType {
	case SubjectUser:
		err = s.db.QueryRowContext(ctx, `SELECT username FROM users WHERE id = ?`, subjectID).Scan(&name)
	case SubjectGroup:
		err = s.db.QueryRowContext(ctx, `SELECT name FROM user_groups WHERE id = ?`, subjectID).Scan(&name)
	default:
		return "", ErrBadInput
	}
	return name, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanGrant(s scanner) (Grant, error) {
	var g Grant
	var subjectName sql.NullString
	var created string
	if err := s.Scan(&g.ID, &g.AssetID, &g.AssetName, &g.SubjectType, &g.SubjectID, &subjectName, &g.CreatedBy, &created); err != nil {
		return Grant{}, err
	}
	if subjectName.Valid {
		g.SubjectName = subjectName.String
	}
	var err error
	g.CreatedAt, err = identity.ParseTime(created)
	if err != nil {
		return Grant{}, err
	}
	return g, nil
}
