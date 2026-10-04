package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode"
)

// Group is a named set of users. Membership is group_id plus user_id.
type Group struct {
	ID        string
	Name      string
	CreatedAt time.Time
	Members   int
}

// Member is one user in a group.
type Member struct {
	UserID   string
	Username string
	Role     string
}

func ValidGroupName(s string) bool {
	if s == "" || s != strings.TrimSpace(s) {
		return false
	}
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
		n++
	}
	return n >= 1 && n <= 64
}

func CreateGroup(ctx context.Context, db DBTX, name string, now time.Time) (Group, error) {
	name = strings.TrimSpace(name)
	if !ValidGroupName(name) {
		return Group{}, ErrBadName
	}
	id, err := NewID()
	if err != nil {
		return Group{}, err
	}
	ts := FormatTime(now)
	if _, err := db.ExecContext(ctx, `INSERT INTO user_groups (id, name, created_at) VALUES (?, ?, ?)`, id, name, ts); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Group{}, ErrDuplicate
		}
		return Group{}, err
	}
	return Group{ID: id, Name: name, CreatedAt: now.UTC()}, nil
}

func ListGroups(ctx context.Context, db DBTX) ([]Group, error) {
	rows, err := db.QueryContext(ctx, `SELECT g.id, g.name, g.created_at,
		(SELECT COUNT(*) FROM group_members m WHERE m.group_id = g.id)
		FROM user_groups g ORDER BY g.name, g.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func GetGroup(ctx context.Context, db DBTX, id string) (Group, error) {
	row := db.QueryRowContext(ctx, `SELECT g.id, g.name, g.created_at,
		(SELECT COUNT(*) FROM group_members m WHERE m.group_id = g.id)
		FROM user_groups g WHERE g.id = ?`, id)
	g, err := scanGroup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	return g, err
}

func ListMembers(ctx context.Context, db DBTX, groupID string) ([]Member, error) {
	rows, err := db.QueryContext(ctx, `SELECT u.id, u.username, u.role
		FROM group_members m JOIN users u ON u.id = m.user_id
		WHERE m.group_id = ? ORDER BY u.username, u.id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Username, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func AddMember(ctx context.Context, db DBTX, groupID, userID string) error {
	if groupID == "" || userID == "" {
		return ErrNotFound
	}
	_, err := db.ExecContext(ctx, `INSERT INTO group_members (group_id, user_id) VALUES (?, ?)`, groupID, userID)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "UNIQUE") {
			return ErrDuplicate
		}
		if strings.Contains(msg, "FOREIGN KEY") {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func RemoveMember(ctx context.Context, db DBTX, groupID, userID string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, groupID, userID)
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

// DeleteGroup removes the group. Membership rows follow the foreign key.
// Grants whose subject is this group are removed in the same transaction.
func DeleteGroup(ctx context.Context, db *sql.DB, id string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_groups WHERE id = ?`, id).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM grants WHERE subject_type = 'group' AND subject_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_groups WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteUser removes the user. Membership rows follow the foreign key.
// Grants whose subject is this user are removed in the same transaction.
// The last remaining administrator cannot be deleted.
func DeleteUser(ctx context.Context, db *sql.DB, id string) error {
	if id == "" {
		return ErrNotFound
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var role string
	err = tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, id).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if role == RoleAdmin {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ?`, RoleAdmin).Scan(&n); err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM grants WHERE subject_type = 'user' AND subject_id = ?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func scanGroup(s scanner) (Group, error) {
	var g Group
	var created string
	if err := s.Scan(&g.ID, &g.Name, &created, &g.Members); err != nil {
		return Group{}, err
	}
	var err error
	g.CreatedAt, err = ParseTime(created)
	if err != nil {
		return Group{}, err
	}
	return g, nil
}
