package auth

import (
	"strings"
	"testing"
)

func TestVerifyRejectsMalformed(t *testing.T) {
	if verifyPassword("nope", "x") {
		t.Fatal("malformed hash verified")
	}
}

func TestHashPHCAndVerify(t *testing.T) {
	h, err := hashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "$argon2id$v=19$m=65536,t=3,p=4$"
	if !strings.HasPrefix(h, prefix) {
		t.Fatalf("phc = %s", h)
	}
	if !verifyPassword(h, "secret") {
		t.Fatal("expected match")
	}
	if verifyPassword(h, "other") {
		t.Fatal("expected mismatch")
	}
}
