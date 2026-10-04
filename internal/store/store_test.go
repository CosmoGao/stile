package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestMigrateOnceAndForeignKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Stile.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	var names []string
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	for _, want := range []string{"users", "login_tokens", "schema_migrations"} {
		if !got[want] {
			t.Fatalf("missing table %s in %v", want, names)
		}
	}
	for _, n := range names {
		if n != "users" && n != "login_tokens" && n != "schema_migrations" {
			t.Fatalf("unexpected table %s", n)
		}
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO login_tokens (id, user_id, token_hash, expires_at, created_at) VALUES ('t', 'missing', 'h', 'e', 'c')`); err == nil {
		t.Fatal("foreign key did not reject a token without a user")
	}

	db.Close()
	db2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var n int
	if err := db2.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("migrations applied %d times", n)
	}
	_ = sql.ErrNoRows
}
