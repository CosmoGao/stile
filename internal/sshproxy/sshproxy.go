package sshproxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const handshakeTimeout = 15 * time.Second

var (
	// ErrHostKeyMismatch means the server key is not the registered fingerprint.
	// Authentication has not started.
	ErrHostKeyMismatch = errors.New("host key mismatch")
	ErrBadTarget       = errors.New("bad ssh target")
	errStopBeforeAuth  = errors.New("stop before authentication")
)

// SecretFunc returns a password or an unencrypted PEM private key.
// Connect calls it only after the host key fingerprint matches.
type SecretFunc func() (string, error)

// Target is one SSH dial. Password and PrivateKey are exclusive.
// Leave both nil for no authentication; Probe does not use Target.
type Target struct {
	Host        string
	Port        int
	User        string
	Fingerprint string
	Password    SecretFunc
	PrivateKey  SecretFunc
}

// Terminal is an interactive SSH session. It has a PTY and a shell.
// It does not request port forwarding.
type Terminal struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	once    sync.Once
}

// Probe opens a TCP connection, runs the SSH key exchange, and disconnects.
// It does not read a credential and does not start user authentication.
func Probe(ctx context.Context, host string, port int) (string, error) {
	if strings.TrimSpace(host) == "" || port < 1 || port > 65535 {
		return "", ErrBadTarget
	}
	conn, err := dial(ctx, host, port)
	if err != nil {
		return "", err
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	var fingerprint string
	cfg := &ssh.ClientConfig{
		User: "probe",
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fingerprint = ssh.FingerprintSHA256(key)
			return errStopBeforeAuth
		},
		Timeout: handshakeTimeout,
	}
	sshConn, _, _, err := ssh.NewClientConn(conn, net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if sshConn != nil {
		sshConn.Close()
	}
	if fingerprint == "" {
		if err == nil {
			err = errors.New("ssh: no host key")
		}
		return "", err
	}
	return fingerprint, nil
}

// Connect checks the host key before it asks for the password or private key.
// On success the session has a PTY and a shell. The handshake deadline is
// cleared; this is not a session idle timeout or a maximum duration.
func Connect(ctx context.Context, target Target) (*Terminal, error) {
	host := strings.TrimSpace(target.Host)
	user := strings.TrimSpace(target.User)
	want := strings.TrimSpace(target.Fingerprint)
	if host == "" || user == "" || want == "" || target.Port < 1 || target.Port > 65535 {
		return nil, ErrBadTarget
	}
	if (target.Password == nil) == (target.PrivateKey == nil) {
		return nil, ErrBadTarget
	}
	conn, err := dial(ctx, host, target.Port)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	mismatch := false
	cfg := &ssh.ClientConfig{
		User: user,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				mismatch = true
				return ErrHostKeyMismatch
			}
			return nil
		},
		Auth:    []ssh.AuthMethod{authMethod(target)},
		Timeout: handshakeTimeout,
	}
	addr := net.JoinHostPort(host, strconv.Itoa(target.Port))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		if mismatch || errors.Is(err, ErrHostKeyMismatch) {
			return nil, ErrHostKeyMismatch
		}
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		sshConn.Close()
		return nil, err
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		session.Close()
		client.Close()
		return nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, err
	}
	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, err
	}
	return &Terminal{client: client, session: session, stdin: stdin, stdout: stdout}, nil
}

func (t *Terminal) Read(p []byte) (int, error) {
	return t.stdout.Read(p)
}

func (t *Terminal) Write(p []byte) (int, error) {
	return t.stdin.Write(p)
}

func (t *Terminal) Resize(cols, rows int) error {
	if cols < 1 || rows < 1 || cols > 500 || rows > 500 {
		return ErrBadTarget
	}
	return t.session.WindowChange(rows, cols)
}

func (t *Terminal) Close() error {
	var err error
	t.once.Do(func() {
		if t.session != nil {
			err = t.session.Close()
		}
		if t.client != nil {
			if cerr := t.client.Close(); err == nil {
				err = cerr
			}
		}
	})
	return err
}

func authMethod(target Target) ssh.AuthMethod {
	if target.Password != nil {
		return ssh.PasswordCallback(func() (string, error) {
			return target.Password()
		})
	}
	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		pemBytes, err := target.PrivateKey()
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey([]byte(pemBytes))
		if err != nil {
			return nil, err
		}
		return []ssh.Signer{signer}, nil
	})
}

func dial(ctx context.Context, host string, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: handshakeTimeout}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}
