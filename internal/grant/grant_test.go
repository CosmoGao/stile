package grant_test

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CosmoGao/stile/internal/asset"
	"github.com/CosmoGao/stile/internal/grant"
	"github.com/CosmoGao/stile/internal/identity"
	"github.com/CosmoGao/stile/internal/store"
)

func TestUnionAndCascades(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "Stile.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	if err := identity.InsertUser(ctx, db, "admin", "hash", identity.RoleAdmin, now); err != nil {
		t.Fatal(err)
	}
	if err := identity.InsertUser(ctx, db, "alice", "hash", identity.RoleUser, now); err != nil {
		t.Fatal(err)
	}
	if err := identity.InsertUser(ctx, db, "bob", "hash", identity.RoleUser, now); err != nil {
		t.Fatal(err)
	}
	admin, err := identity.GetByUsername(ctx, db, "admin")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := identity.GetByUsername(ctx, db, "alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.GetByUsername(ctx, db, "bob")
	if err != nil {
		t.Fatal(err)
	}
	assets := asset.New(db, func() time.Time { return now })
	mk := func(name, host string) asset.Asset {
		t.Helper()
		a, err := assets.Create(ctx, asset.Input{Name: name, Protocol: "ssh", Host: host})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	direct := mk("direct", "192.0.2.10")
	grouped := mk("grouped", "192.0.2.20")
	both := mk("both", "192.0.2.30")
	hidden := mk("hidden", "192.0.2.40")
	ops, err := identity.CreateGroup(ctx, db, "ops", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.AddMember(ctx, db, ops.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := identity.AddMember(ctx, db, ops.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	g := grant.New(db, func() time.Time { return now })
	if _, err := g.Add(ctx, direct.ID, grant.SubjectUser, alice.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Add(ctx, direct.ID, grant.SubjectUser, alice.ID, admin.ID); err != grant.ErrDuplicate {
		t.Fatalf("duplicate grant: %v", err)
	}
	if _, err := g.Add(ctx, grouped.ID, grant.SubjectGroup, ops.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Add(ctx, both.ID, grant.SubjectUser, alice.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Add(ctx, both.ID, grant.SubjectGroup, ops.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	var pair int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM grants WHERE asset_id = ? AND subject_type = 'user' AND subject_id = ?`, direct.ID, alice.ID).Scan(&pair); err != nil || pair != 1 {
		t.Fatalf("pair rows %d %v", pair, err)
	}

	got, err := g.ListForUser(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if names(got) != "both,direct,grouped" {
		t.Fatalf("alice sees %s", names(got))
	}
	typ := reflect.TypeOf(asset.UserAsset{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		if strings.Contains(name, "credential") || strings.Contains(name, "secret") {
			t.Fatalf("user asset field %s", typ.Field(i).Name)
		}
	}
	bobSeen, err := g.ListForUser(ctx, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if names(bobSeen) != "both,grouped" {
		t.Fatalf("bob sees %s", names(bobSeen))
	}
	for _, id := range []string{direct.ID, grouped.ID, both.ID, hidden.ID} {
		ok, err := g.Allowed(ctx, admin.ID, id)
		if err != nil || ok {
			t.Fatalf("admin allowed %s: %v %v", id, ok, err)
		}
	}
	ok, err := g.Allowed(ctx, alice.ID, hidden.ID)
	if err != nil || ok {
		t.Fatalf("alice hidden: %v %v", ok, err)
	}
	ok, err = g.Allowed(ctx, alice.ID, grouped.ID)
	if err != nil || !ok {
		t.Fatalf("alice grouped: %v %v", ok, err)
	}

	if err := identity.DeleteGroup(ctx, db, ops.ID); err != nil {
		t.Fatal(err)
	}
	var groupGrants, members int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM grants WHERE subject_type = 'group' AND subject_id = ?`, ops.ID).Scan(&groupGrants); err != nil || groupGrants != 0 {
		t.Fatalf("group grants left %d %v", groupGrants, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_members WHERE group_id = ?`, ops.ID).Scan(&members); err != nil || members != 0 {
		t.Fatalf("members left %d %v", members, err)
	}
	got, err = g.ListForUser(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if names(got) != "both,direct" {
		t.Fatalf("alice after group delete %s", names(got))
	}
	ok, err = g.Allowed(ctx, bob.ID, grouped.ID)
	if err != nil || ok {
		t.Fatalf("bob still allowed via deleted group: %v %v", ok, err)
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, direct.ID); err != nil {
		t.Fatal(err)
	}
	var assetGrants int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM grants WHERE asset_id = ?`, direct.ID).Scan(&assetGrants); err != nil || assetGrants != 0 {
		t.Fatalf("asset grants left %d %v", assetGrants, err)
	}

	extra, err := identity.CreateGroup(ctx, db, "extra", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.AddMember(ctx, db, extra.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Add(ctx, hidden.ID, grant.SubjectUser, bob.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	if err := identity.DeleteUser(ctx, db, bob.ID); err != nil {
		t.Fatal(err)
	}
	var userGrants, bobMembers, bobRows int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM grants WHERE subject_type = 'user' AND subject_id = ?`, bob.ID).Scan(&userGrants); err != nil || userGrants != 0 {
		t.Fatalf("user grants left %d %v", userGrants, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_members WHERE user_id = ?`, bob.ID).Scan(&bobMembers); err != nil || bobMembers != 0 {
		t.Fatalf("user memberships left %d %v", bobMembers, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id = ?`, bob.ID).Scan(&bobRows); err != nil || bobRows != 0 {
		t.Fatal(err)
	}
	if _, err := identity.GetGroup(ctx, db, extra.ID); err != nil {
		t.Fatal(err)
	}
	cols := map[string]bool{}
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(grants)`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		cols[name] = true
	}
	rows.Close()
	for _, banned := range []string{"permission", "upload", "download", "edit", "rename", "clipboard", "kind"} {
		if cols[banned] {
			t.Fatalf("grants has %s", banned)
		}
	}
	for _, want := range []string{"id", "asset_id", "subject_type", "subject_id", "created_by", "created_at"} {
		if !cols[want] {
			t.Fatalf("grants missing %s", want)
		}
	}
}

func names(list []asset.UserAsset) string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Name)
	}
	return strings.Join(out, ",")
}
