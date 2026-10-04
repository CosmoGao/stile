package config

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultPath = "/etc/Stile/stile.conf"

// Config is everything the process needs to start.
// SessionTTL, LockoutFailures, and LockoutDuration have no product default.
// Callers must set them from a config file or the environment.
type Config struct {
	Listen          string
	Database        string
	MasterKey       string
	SessionTTL      time.Duration
	LockoutFailures int
	LockoutDuration time.Duration
	// GuacdAddress is optional. Empty means RDP cannot dial. SSH does not use it.
	GuacdAddress string
}

// Load reads STILE_CONFIG, or /etc/Stile/stile.conf when that file exists,
// then applies environment variables over the file. Missing policy values
// are an error. They are not filled in from constants.
func Load() (Config, error) {
	var cfg Config
	path := os.Getenv("STILE_CONFIG")
	if path == "" {
		if _, err := os.Stat(defaultPath); err == nil {
			path = defaultPath
		}
	}
	if path != "" {
		parsed, err := parseFile(path)
		if err != nil {
			return Config{}, err
		}
		cfg = parsed
	}
	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	var missing []string
	if c.Listen == "" {
		missing = append(missing, "listen")
	}
	if c.Database == "" {
		missing = append(missing, "database")
	}
	if c.MasterKey == "" {
		missing = append(missing, "master_key")
	}
	if c.SessionTTL <= 0 {
		missing = append(missing, "session_ttl")
	}
	if c.LockoutFailures <= 0 {
		missing = append(missing, "lockout_failures")
	}
	if c.LockoutDuration <= 0 {
		missing = append(missing, "lockout_duration")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing or invalid configuration: %s", strings.Join(missing, ", "))
	}
	// Cookie Max-Age is whole seconds. This is a transport floor, not a product lifetime.
	if c.SessionTTL < time.Second {
		return errors.New("session_ttl must be at least one second")
	}
	return nil
}

func parseFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var cfg Config
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return Config{}, fmt.Errorf("%s:%d: want key and value", path, lineNo)
		}
		key, val := fields[0], fields[1]
		if seen[key] {
			return Config{}, fmt.Errorf("%s:%d: duplicate key %s", path, lineNo, key)
		}
		seen[key] = true
		if err := applyKey(&cfg, key, val); err != nil {
			return Config{}, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyKey(cfg *Config, key, val string) error {
	switch key {
	case "listen":
		cfg.Listen = val
	case "database":
		cfg.Database = val
	case "master_key":
		cfg.MasterKey = val
	case "session_ttl":
		d, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("session_ttl: %w", err)
		}
		cfg.SessionTTL = d
	case "lockout_failures":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("lockout_failures: %w", err)
		}
		cfg.LockoutFailures = n
	case "lockout_duration":
		d, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("lockout_duration: %w", err)
		}
		cfg.LockoutDuration = d
	case "guacd":
		cfg.GuacdAddress = val
	default:
		return fmt.Errorf("unknown key %s", key)
	}
	return nil
}

func applyEnv(cfg *Config) error {
	if v := os.Getenv("STILE_LISTEN"); v != "" {
		cfg.Listen = v
	} else if v := os.Getenv("STILE_ADDR"); v != "" && os.Getenv("STILE_LISTEN") == "" {
		cfg.Listen = v
	}
	if v := os.Getenv("STILE_DATABASE"); v != "" {
		cfg.Database = v
	}
	if v := os.Getenv("STILE_MASTER_KEY"); v != "" {
		cfg.MasterKey = v
	}
	if v := os.Getenv("STILE_SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("STILE_SESSION_TTL: %w", err)
		}
		cfg.SessionTTL = d
	}
	if v := os.Getenv("STILE_LOCKOUT_FAILURES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("STILE_LOCKOUT_FAILURES: %w", err)
		}
		cfg.LockoutFailures = n
	}
	if v := os.Getenv("STILE_LOCKOUT_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("STILE_LOCKOUT_DURATION: %w", err)
		}
		cfg.LockoutDuration = d
	}
	if v := os.Getenv("GUACD_ADDRESS"); v != "" {
		cfg.GuacdAddress = v
	}
	return nil
}

// LoadOrCreateMasterKey reads a raw 32-byte key. If the file is missing,
// it generates one. This is process startup, not a subcommand.
// The key is not logged and is not stored in SQLite.
func LoadOrCreateMasterKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
			return nil, err
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			return nil, err
		}
		return buf, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("master key file must contain exactly 32 bytes")
	}
	out := make([]byte, 32)
	copy(out, b)
	return out, nil
}

func dirOf(path string) string {
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "."
	}
	return path[:i]
}
