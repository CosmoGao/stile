package credential

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CosmoGao/stile/internal/store"
	"golang.org/x/crypto/ssh"
)

func TestPasswordIsCiphertextBoundToID(t *testing.T) {
	svc, db, path := testService(t)
	const secret = "pw-plain-9f3c1a-4b7e"
	ctx := context.Background()
	created, err := svc.Create(ctx, Input{
		Name: "linux-login", Kind: KindPassword, LoginName: "root", Secret: secret,
		KeyPassphrase: "passphrase-should-not-stick",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Fingerprint != "" {
		t.Fatalf("password fingerprint %q", created.Fingerprint)
	}
	list, err := svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Fingerprint != "" {
		t.Fatalf("list %+v", list)
	}
	var nonce, ct []byte
	if err := db.QueryRow(`SELECT secret_nonce, secret_ciphertext FROM credentials WHERE id = ?`, created.ID).Scan(&nonce, &ct); err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 12 {
		t.Fatalf("nonce length %d", len(nonce))
	}
	if bytes.Contains(ct, []byte(secret)) || bytes.Contains(nonce, []byte(secret)) {
		t.Fatal("database blob contains the password")
	}
	plain, err := open(svc.key, []byte(created.ID), nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != secret {
		t.Fatalf("opened %q", plain)
	}
	if _, err := open(svc.key, []byte("other-credential-id"), nonce, ct); err == nil {
		t.Fatal("ciphertext opened under a different credential id")
	}
	got, revealed, err := svc.Reveal(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revealed != secret || got.ID != created.ID {
		t.Fatalf("reveal %q %+v", revealed, got)
	}
	raw := readDB(t, path)
	for _, banned := range []string{secret, "passphrase-should-not-stick"} {
		if bytes.Contains(raw, []byte(banned)) {
			t.Fatalf("database file contains %q", banned)
		}
	}
}

func TestPrivateKeyPassphraseUnwrappedAndNotStored(t *testing.T) {
	svc, db, path := testService(t)
	const pass = "key-passphrase-not-in-db-44"
	pemText, wantFP := testKey(t, pass)
	ctx := context.Background()
	if _, err := svc.Create(ctx, Input{
		Name: "locked", Kind: KindPrivateKey, LoginName: "root", Secret: pemText,
	}); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("missing passphrase: %v", err)
	}
	if _, err := svc.Create(ctx, Input{
		Name: "locked", Kind: KindPrivateKey, LoginName: "root", Secret: pemText, KeyPassphrase: "nope",
	}); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("failed imports stored %d rows", n)
	}
	created, err := svc.Create(ctx, Input{
		Name: "locked", Kind: KindPrivateKey, LoginName: "root", Secret: pemText, KeyPassphrase: pass,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Fingerprint != wantFP {
		t.Fatalf("fingerprint %s want %s", created.Fingerprint, wantFP)
	}
	_, revealed, err := svc.Reveal(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(revealed, pass) {
		t.Fatal("revealed key contains the passphrase")
	}
	rawKey, err := ssh.ParseRawPrivateKey([]byte(revealed))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(signer.PublicKey()) != wantFP {
		t.Fatal("revealed key fingerprint mismatch")
	}
	raw := readDB(t, path)
	for _, banned := range []string{pass, "PRIVATE KEY"} {
		if bytes.Contains(raw, []byte(banned)) {
			t.Fatalf("database file contains %q", banned)
		}
	}
	line := pemBodyLine(pemText)
	if line == "" || bytes.Contains(raw, []byte(line)) {
		t.Fatal("encrypted key body is in the database")
	}
	if strings.Contains(revealed, line) {
		t.Fatal("revealed key still has the encrypted body")
	}
}

func TestDeleteBlockedWhileReferenced(t *testing.T) {
	svc, db, _ := testService(t)
	ctx := context.Background()
	created, err := svc.Create(ctx, Input{Name: "shared", Kind: KindPassword, LoginName: "root", Secret: "secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	insertAsset := func(id, host string) {
		t.Helper()
		_, err := db.Exec(`INSERT INTO assets (id, name, protocol, host, port, credential_id, created_at, updated_at) VALUES (?, ?, 'ssh', ?, 22, ?, 't', 't')`, id, id, host, created.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	insertAsset("asset-a", "192.0.2.1")
	insertAsset("asset-b", "192.0.2.2")
	if err := svc.Delete(ctx, created.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete while two assets reference it: %v", err)
	}
	if _, err := db.Exec(`UPDATE assets SET credential_id = NULL WHERE id = 'asset-a'`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, created.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete while one asset references it: %v", err)
	}
	if _, err := db.Exec(`UPDATE assets SET credential_id = NULL WHERE id = 'asset-b'`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE id = ?`, created.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("credential row remains")
	}
}

func testService(t *testing.T) (*Service, *sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Stile.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return New(db, key, time.Now), db, path
}

func testKey(t *testing.T, passphrase string) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), ssh.FingerprintSHA256(signer.PublicKey())
}

func pemBodyLine(pemText string) string {
	for _, line := range strings.Split(pemText, "\n") {
		if len(line) > 40 && !strings.HasPrefix(line, "-----") {
			return line
		}
	}
	return ""
}

func readDB(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if w, err := os.ReadFile(path + "-wal"); err == nil {
		b = append(b, w...)
	}
	return b
}
