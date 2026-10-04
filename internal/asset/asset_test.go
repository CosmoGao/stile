package asset

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CosmoGao/stile/internal/credential"
	"github.com/CosmoGao/stile/internal/store"
)

func TestUserAssetOmitsCredentialID(t *testing.T) {
	admin := reflect.TypeOf(Asset{})
	user := reflect.TypeOf(UserAsset{})
	if _, ok := admin.FieldByName("CredentialID"); !ok {
		t.Fatal("admin asset has no credential id")
	}
	if _, ok := user.FieldByName("CredentialID"); ok {
		t.Fatal("user asset has credential id")
	}
	for _, typ := range []reflect.Type{admin, user} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, banned := range []string{"password", "secret", "nonce", "cipher", "passphrase", "private"} {
				if strings.Contains(name, banned) {
					t.Fatalf("%s has %s", typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
	a := Asset{
		ID: "id", Name: "n", Protocol: ProtocolSSH, Host: "192.0.2.1", Port: 22,
		CredentialID: "cred", CredentialName: "login", HostKeyFingerprint: "SHA256:x",
	}
	got := a.ForUser()
	if got.ID != "id" || got.Name != "n" || got.Protocol != ProtocolSSH || got.Host != "192.0.2.1" || got.Port != 22 {
		t.Fatalf("%+v", got)
	}
}

func TestDefaultPortsRDPIgnoresFingerprintAndReuse(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "Stile.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	creds := credential.New(db, key, time.Now)
	ctx := context.Background()
	cred, err := creds.Create(ctx, credential.Input{Name: "shared", Kind: credential.KindPassword, LoginName: "root", Secret: "secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	assets := New(db, time.Now)
	rdp, err := assets.Create(ctx, Input{
		Name: "win", Protocol: ProtocolRDP, Host: "192.0.2.10",
		HostKeyFingerprint: "SHA256:should-ignore",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rdp.Port != DefaultRDPPort || rdp.HostKeyFingerprint != "" || rdp.Protocol != ProtocolRDP {
		t.Fatalf("%+v", rdp)
	}
	first, err := assets.Create(ctx, Input{
		Name: "linux-a", Protocol: ProtocolSSH, Host: "192.0.2.1",
		CredentialID: cred.ID, HostKeyFingerprint: "SHA256:pinned-fingerprint",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := assets.Create(ctx, Input{
		Name: "linux-b", Protocol: ProtocolSSH, Host: "192.0.2.2", CredentialID: cred.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Port != DefaultSSHPort || second.Port != DefaultSSHPort {
		t.Fatalf("ports %d %d", first.Port, second.Port)
	}
	if first.CredentialID != cred.ID || second.CredentialID != cred.ID {
		t.Fatalf("credential ids %s %s", first.CredentialID, second.CredentialID)
	}
	if first.HostKeyFingerprint != "SHA256:pinned-fingerprint" || second.HostKeyFingerprint != "" {
		t.Fatalf("fingerprints %q %q", first.HostKeyFingerprint, second.HostKeyFingerprint)
	}
	cleared, err := assets.Update(ctx, first.ID, Input{
		Name: first.Name, Protocol: first.Protocol, Host: first.Host, Port: "22",
		HostKeyFingerprint: first.HostKeyFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleared.CredentialID != "" {
		t.Fatalf("still bound: %+v", cleared)
	}
	p, err := ResolvePort(ProtocolSSH, "2222")
	if err != nil || p != 2222 {
		t.Fatalf("explicit port %d %v", p, err)
	}
	if _, err := ResolvePort(ProtocolRDP, "0"); err == nil {
		t.Fatal("port 0 accepted")
	}
}
