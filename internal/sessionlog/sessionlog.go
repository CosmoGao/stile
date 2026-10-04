package sessionlog

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/CosmoGao/stile/internal/identity"
)

// Entry is one web session row. The product fields are who, which asset,
// when it started, and when it ended. id exists only so the row can be updated.
type Entry struct {
	ID        string
	UserID    string
	AssetID   string
	StartedAt time.Time
	EndedAt   *time.Time
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

// Start records that a web session has been established. It stores only the
// user, the asset, and the start time.
func (s *Service) Start(ctx context.Context, userID, assetID string) (string, error) {
	if userID == "" || assetID == "" {
		return "", errors.New("missing session subject")
	}
	id, err := identity.NewID()
	if err != nil {
		return "", err
	}
	started := s.now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO web_sessions (id, user_id, asset_id, started_at) VALUES (?, ?, ?, ?)`,
		id, userID, assetID, identity.FormatTime(started))
	if err != nil {
		return "", err
	}
	return id, nil
}

// End writes the end time once. A second call does not change the first time.
func (s *Service) End(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE web_sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL`,
		identity.FormatTime(s.now().UTC()), id)
	return err
}
