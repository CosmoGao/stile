package auth

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSealBindsUserID(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := seal(key, []byte("user-a"), []byte("seed"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := open(key, []byte("user-a"), nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, []byte("seed")) {
		t.Fatalf("plain = %q", plain)
	}
	if _, err := open(key, []byte("user-b"), nonce, ct); err == nil {
		t.Fatal("ciphertext opened under a different user id")
	}
	if bytes.Equal(ct, []byte("seed")) {
		t.Fatal("ciphertext is plaintext")
	}
}
