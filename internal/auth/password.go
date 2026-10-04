package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// RFC 9106 second recommended option. These are KDF parameters, not lockout policy.
const (
	argonMemoryKiB = 65536
	argonTime      = 3
	argonThreads   = 4
	argonSaltLen   = 16
	argonKeyLen    = 32
)

func hashPassword(password string) (string, error) {
	if password == "" || len(password) > 1024 {
		return "", ErrBadPassword
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemoryKiB,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

func verifyPassword(phc, password string) bool {
	if password == "" || len(password) > 1024 {
		return false
	}
	mem, timeCost, threads, salt, want, err := parsePHC(phc)
	if err != nil {
		return false
	}
	// Ceiling so a corrupt hash cannot ask for unbounded memory.
	// New hashes always use the RFC 9106 second option.
	if mem == 0 || mem > 262144 || timeCost == 0 || timeCost > 8 || threads == 0 || threads > 8 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, mem, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parsePHC(phc string) (mem, timeCost uint32, threads uint8, salt, hash []byte, err error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return 0, 0, 0, nil, nil, errors.New("bad phc")
	}
	var sawM, sawT, sawP bool
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return 0, 0, 0, nil, nil, errors.New("bad phc params")
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, 0, 0, nil, nil, err
		}
		switch k {
		case "m":
			mem = uint32(n)
			sawM = true
		case "t":
			timeCost = uint32(n)
			sawT = true
		case "p":
			if n > 255 {
				return 0, 0, 0, nil, nil, errors.New("bad parallelism")
			}
			threads = uint8(n)
			sawP = true
		default:
			return 0, 0, 0, nil, nil, errors.New("bad phc param")
		}
	}
	if !sawM || !sawT || !sawP {
		return 0, 0, 0, nil, nil, errors.New("incomplete phc params")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}
	if len(salt) == 0 || len(hash) == 0 {
		return 0, 0, 0, nil, nil, errors.New("empty phc material")
	}
	return mem, timeCost, threads, salt, hash, nil
}

var dummy struct {
	once sync.Once
	phc  string
	err  error
}

func verifyUnknown(password string) {
	dummy.once.Do(func() {
		dummy.phc, dummy.err = hashPassword("not-a-real-password")
	})
	if dummy.err != nil {
		return
	}
	verifyPassword(dummy.phc, password)
}
