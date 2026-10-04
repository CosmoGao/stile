package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"STILE_CONFIG",
		"STILE_LISTEN",
		"STILE_ADDR",
		"STILE_DATABASE",
		"STILE_MASTER_KEY",
		"STILE_SESSION_TTL",
		"STILE_LOCKOUT_FAILURES",
		"STILE_LOCKOUT_DURATION",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadRejectsMissingLockout(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "stile.conf")
	body := "listen 127.0.0.1:9\ndatabase " + filepath.Join(dir, "x.db") + "\nmaster_key " + filepath.Join(dir, "k") + "\nsession_ttl 2h\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STILE_CONFIG", path)
	if _, err := Load(); err == nil {
		t.Fatal("missing lockout policy was accepted")
	}
}

func TestEnvOverridesFile(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "stile.conf")
	body := stringsJoin([]string{
		"listen 127.0.0.1:9",
		"database " + filepath.Join(dir, "a.db"),
		"master_key " + filepath.Join(dir, "a.key"),
		"session_ttl 2h",
		"lockout_failures 2",
		"lockout_duration 30s",
		"",
	})
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STILE_CONFIG", path)
	t.Setenv("STILE_LOCKOUT_FAILURES", "7")
	t.Setenv("STILE_LOCKOUT_DURATION", "45s")
	t.Setenv("STILE_ADDR", "127.0.0.1:11")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LockoutFailures != 7 {
		t.Fatalf("failures = %d", cfg.LockoutFailures)
	}
	if cfg.LockoutDuration != 45*time.Second {
		t.Fatalf("duration = %s", cfg.LockoutDuration)
	}
	if cfg.Listen != "127.0.0.1:11" {
		t.Fatalf("listen = %s", cfg.Listen)
	}
	if cfg.SessionTTL != 2*time.Hour {
		t.Fatalf("ttl = %s", cfg.SessionTTL)
	}
}

func TestListenEnvWinsOverAddr(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	t.Setenv("STILE_LISTEN", "127.0.0.1:12")
	t.Setenv("STILE_ADDR", "127.0.0.1:13")
	t.Setenv("STILE_DATABASE", filepath.Join(dir, "a.db"))
	t.Setenv("STILE_MASTER_KEY", filepath.Join(dir, "a.key"))
	t.Setenv("STILE_SESSION_TTL", "3h")
	t.Setenv("STILE_LOCKOUT_FAILURES", "2")
	t.Setenv("STILE_LOCKOUT_DURATION", "30s")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:12" {
		t.Fatalf("listen = %s", cfg.Listen)
	}
}

func TestExampleConfigParses(t *testing.T) {
	clearEnv(t)
	path := filepath.Join("..", "..", "config.example")
	t.Setenv("STILE_CONFIG", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen == "" || cfg.Database == "" || cfg.MasterKey == "" {
		t.Fatalf("example missing paths: %+v", cfg)
	}
	if cfg.SessionTTL <= 0 || cfg.LockoutFailures < 1 || cfg.LockoutDuration <= 0 {
		t.Fatalf("example policy not positive: %+v", cfg)
	}
}

func TestMasterKeyCreateAndReject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	key, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("len = %d", len(key))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o", info.Mode().Perm())
	}
	again, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(key) {
		t.Fatal("key changed")
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateMasterKey(path); err == nil {
		t.Fatal("short key accepted")
	}
}

func stringsJoin(lines []string) string {
	out := ""
	for i, line := range lines {
		if i > 0 {
			out += "\n"
		}
		out += line
	}
	return out
}
