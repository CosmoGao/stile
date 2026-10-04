package rdpproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const handshakeTimeout = 15 * time.Second

var (
	// ErrHandshake means guacd did not complete the RDP handshake.
	// The password is not included.
	ErrHandshake = errors.New("guacd handshake failed")
	ErrBadTarget = errors.New("bad rdp target")
)

// DialFunc opens a connection to guacd. Tests replace it with a local endpoint.
type DialFunc func(ctx context.Context, address string) (net.Conn, error)

// Target is what Stile fills in for guacd. The browser does not supply these.
type Target struct {
	Host     string
	Port     int
	Username string
	Password string
	Width    int
	Height   int
	DPI      int
	Timezone string
}

// ConnectArgs builds guacd connect values in the order of the args instruction.
// Hostname, port, username, and password come from target. Disk and file
// transfer stay off. Every other parameter is empty, so the browser cannot
// turn a feature on.
func ConnectArgs(names []string, target Target) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = connectValue(name, target)
	}
	return out
}

func connectValue(name string, target Target) string {
	switch name {
	case "hostname":
		return target.Host
	case "port":
		return strconv.Itoa(target.Port)
	case "username":
		return target.Username
	case "password":
		return target.Password
	case "enable-drive", "create-drive-path", "enable-printing", "enable-sftp",
		"create-recording-path", "recording-include-keys", "wol-send-packet":
		return "false"
	case "disable-download", "disable-upload", "sftp-disable-download", "sftp-disable-upload":
		return "true"
	default:
		return ""
	}
}

// Session is a guacd connection after the handshake has completed.
// It does not retain the password.
type Session struct {
	conn net.Conn
	rd   *Reader
	once sync.Once
}

// Handshake dials guacd, selects RDP, and sends the connection parameters.
// A nil dial uses TCP. The returned session is ready to proxy. Its buffer
// may already hold instructions that arrived with the ready reply.
func Handshake(ctx context.Context, address string, target Target, dial DialFunc) (*Session, error) {
	address = strings.TrimSpace(address)
	target.Host = strings.TrimSpace(target.Host)
	target.Username = strings.TrimSpace(target.Username)
	target.Timezone = strings.TrimSpace(target.Timezone)
	if address == "" || target.Host == "" || target.Username == "" || target.Port < 1 || target.Port > 65535 {
		return nil, ErrBadTarget
	}
	if target.Width < 1 {
		target.Width = 1024
	}
	if target.Height < 1 {
		target.Height = 768
	}
	if target.DPI < 1 {
		target.DPI = 96
	}
	if dial == nil {
		dial = defaultDial
	}
	conn, err := dial(ctx, address)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, err
	}
	rd := NewReader(conn)
	if err := writeFull(conn, Encode("select", "rdp")); err != nil {
		return nil, ErrHandshake
	}
	opcode, names, _, err := rd.Next()
	if err != nil || opcode != "args" || len(names) == 0 {
		return nil, ErrHandshake
	}
	writes := [][]byte{
		Encode("size", strconv.Itoa(target.Width), strconv.Itoa(target.Height), strconv.Itoa(target.DPI)),
		Encode("audio"),
		Encode("video"),
		Encode("image", "image/png", "image/jpeg"),
	}
	if target.Timezone != "" {
		writes = append(writes, Encode("timezone", target.Timezone))
	}
	connectArgs := make([]string, 0, 1+len(names))
	connectArgs = append(connectArgs, protocolVersion)
	connectArgs = append(connectArgs, ConnectArgs(names, target)...)
	writes = append(writes, Encode("connect", connectArgs...))
	for _, msg := range writes {
		if err := writeFull(conn, msg); err != nil {
			return nil, ErrHandshake
		}
	}
	opcode, _, _, err = rd.Next()
	if err != nil || opcode != "ready" {
		return nil, ErrHandshake
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return &Session{conn: conn, rd: rd}, nil
}

func (s *Session) Next() (opcode string, args []string, raw []byte, err error) {
	return s.rd.Next()
}

func (s *Session) Write(p []byte) error {
	return writeFull(s.conn, p)
}

func (s *Session) Close() error {
	var err error
	s.once.Do(func() {
		err = s.conn.Close()
	})
	return err
}

func defaultDial(ctx context.Context, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: handshakeTimeout}
	return d.DialContext(ctx, "tcp", address)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
