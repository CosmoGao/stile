package sessionlog

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/CosmoGao/stile/internal/store"
)

func TestSessionRowShape(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	svc := New(db, func() time.Time { return now })
	id, err := svc.Start(ctx, "user-1", "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	svc = New(db, func() time.Time { return later })
	if err := svc.End(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := svc.End(ctx, id); err != nil {
		t.Fatal(err)
	}
	var userID, assetID, started, ended string
	if err := db.QueryRowContext(ctx, `SELECT user_id, asset_id, started_at, ended_at FROM web_sessions WHERE id = ?`, id).Scan(&userID, &assetID, &started, &ended); err != nil {
		t.Fatal(err)
	}
	if userID != "user-1" || assetID != "asset-1" || started == "" || ended == "" {
		t.Fatalf("row %s %s %s %s", userID, assetID, started, ended)
	}
	if ended != later.Format(time.RFC3339Nano) {
		t.Fatalf("end rewritten or wrong: %s", ended)
	}
	cols := map[string]bool{}
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(web_sessions)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"id", "user_id", "asset_id", "started_at", "ended_at"}
	if len(cols) != len(want) {
		t.Fatalf("columns %v", cols)
	}
	for _, name := range want {
		if !cols[name] {
			t.Fatalf("missing %s in %v", name, cols)
		}
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "Stile.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
