package sshproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fakeServer struct {
	ln       net.Listener
	cfg      *ssh.ServerConfig
	fp       string
	password string
	userKey  ssh.PublicKey

	passwordCalls atomic.Int32
	keyCalls      atomic.Int32
	conns         atomic.Int32
	ptyCols       atomic.Uint32
	ptyRows       atomic.Uint32
	winCols       atomic.Uint32
	winRows       atomic.Uint32

	mu      sync.Mutex
	methods []string
	chans   []string
	globals []string
}

func startFake(t *testing.T, password string, userKey ssh.PublicKey) *fakeServer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{
		ln:       ln,
		fp:       ssh.FingerprintSHA256(hostSigner.PublicKey()),
		password: password,
		userKey:  userKey,
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.passwordCalls.Add(1)
			if s.password != "" && subtle.ConstantTimeCompare(pass, []byte(s.password)) == 1 {
				return nil, nil
			}
			return nil, errors.New("no")
		},
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.keyCalls.Add(1)
			if s.userKey != nil && bytes.Equal(key.Marshal(), s.userKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("no")
		},
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			s.mu.Lock()
			s.methods = append(s.methods, method)
			s.mu.Unlock()
		},
	}
	cfg.AddHostKey(hostSigner)
	s.cfg = cfg
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *fakeServer) hostPort() (string, int) {
	host, portText, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		return "", 0
	}
	port := 0
	for _, c := range portText {
		port = port*10 + int(c-'0')
	}
	return host, port
}

func (s *fakeServer) serve(conn net.Conn) {
	s.conns.Add(1)
	sc, chans, reqs, err := ssh.NewServerConn(conn, s.cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go func() {
		for req := range reqs {
			s.mu.Lock()
			s.globals = append(s.globals, req.Type)
			s.mu.Unlock()
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()
	for ch := range chans {
		s.mu.Lock()
		s.chans = append(s.chans, ch.ChannelType())
		s.mu.Unlock()
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.session(channel, requests)
	}
}

func (s *fakeServer) session(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requests {
		switch req.Type {
		case "pty-req":
			var msg struct {
				Term          string
				Cols, Rows    uint32
				Width, Height uint32
				Modes         string
			}
			if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
				s.ptyCols.Store(msg.Cols)
				s.ptyRows.Store(msg.Rows)
			}
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			go func() {
				buf := make([]byte, 1024)
				for {
					n, err := channel.Read(buf)
					if n > 0 {
						_, _ = channel.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		case "window-change":
			var msg struct {
				Cols, Rows    uint32
				Width, Height uint32
			}
			if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
				s.winCols.Store(msg.Cols)
				s.winRows.Store(msg.Rows)
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (s *fakeServer) authMethods() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.methods...)
}

func (s *fakeServer) channelTypes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.chans...)
}

func (s *fakeServer) globalRequests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.globals...)
}

func TestProbeDoesNotAuthenticate(t *testing.T) {
	const password = "probe-must-not-see-this"
	srv := startFake(t, password, nil)
	host, port := srv.hostPort()
	fp, err := Probe(context.Background(), host, port)
	if err != nil {
		t.Fatal(err)
	}
	if fp != srv.fp {
		t.Fatalf("fingerprint %s want %s", fp, srv.fp)
	}
	if srv.conns.Load() < 1 {
		t.Fatal("probe did not connect")
	}
	if srv.passwordCalls.Load() != 0 || srv.keyCalls.Load() != 0 || len(srv.authMethods()) != 0 {
		t.Fatalf("probe authenticated password=%d key=%d methods=%v", srv.passwordCalls.Load(), srv.keyCalls.Load(), srv.authMethods())
	}
}

func TestConnectMismatchDoesNotSendSecrets(t *testing.T) {
	const password = "mismatch-password-should-stay"
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(userPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(block))
	srv := startFake(t, password, userSigner.PublicKey())
	host, port := srv.hostPort()

	var passwordLoads atomic.Int32
	_, err = Connect(context.Background(), Target{
		Host: host, Port: port, User: "root", Fingerprint: "SHA256:not-the-server",
		Password: func() (string, error) {
			passwordLoads.Add(1)
			return password, nil
		},
	})
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("password mismatch err %v", err)
	}
	if passwordLoads.Load() != 0 || srv.passwordCalls.Load() != 0 || len(srv.authMethods()) != 0 {
		t.Fatalf("password sent loads=%d calls=%d methods=%v", passwordLoads.Load(), srv.passwordCalls.Load(), srv.authMethods())
	}

	var keyLoads atomic.Int32
	_, err = Connect(context.Background(), Target{
		Host: host, Port: port, User: "root", Fingerprint: "SHA256:still-wrong",
		PrivateKey: func() (string, error) {
			keyLoads.Add(1)
			return keyPEM, nil
		},
	})
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("key mismatch err %v", err)
	}
	if keyLoads.Load() != 0 || srv.keyCalls.Load() != 0 {
		t.Fatalf("private key sent loads=%d calls=%d methods=%v", keyLoads.Load(), srv.keyCalls.Load(), srv.authMethods())
	}
	for _, method := range srv.authMethods() {
		if method == "password" || method == "publickey" {
			t.Fatalf("auth method %s", method)
		}
	}
}

func TestConnectInteractivePasswordAndKey(t *testing.T) {
	const password = "interactive-password"
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(userPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(block))
	srv := startFake(t, password, userSigner.PublicKey())
	host, port := srv.hostPort()

	term := dialInteractive(t, srv, Target{
		Host: host, Port: port, User: "root", Fingerprint: srv.fp,
		Password: func() (string, error) { return password, nil },
	})
	if !bytes.Contains(readSome(t, term), []byte("ping")) {
		t.Fatal("password session did not echo")
	}
	if err := term.Resize(100, 40); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return srv.winCols.Load() == 100 && srv.winRows.Load() == 40 })
	if srv.ptyCols.Load() != 80 || srv.ptyRows.Load() != 24 {
		t.Fatalf("pty %dx%d", srv.ptyCols.Load(), srv.ptyRows.Load())
	}
	if srv.passwordCalls.Load() != 1 {
		t.Fatalf("password calls %d", srv.passwordCalls.Load())
	}
	term.Close()

	beforeKey := srv.keyCalls.Load()
	term = dialInteractive(t, srv, Target{
		Host: host, Port: port, User: "root", Fingerprint: srv.fp,
		PrivateKey: func() (string, error) { return keyPEM, nil },
	})
	if !bytes.Contains(readSome(t, term), []byte("key")) {
		t.Fatal("key session did not echo")
	}
	term.Close()
	if srv.keyCalls.Load() <= beforeKey {
		t.Fatal("public key was not used")
	}
	for _, kind := range srv.channelTypes() {
		if kind != "session" {
			t.Fatalf("unexpected channel %s", kind)
		}
	}
	for _, kind := range srv.globalRequests() {
		if kind == "tcpip-forward" || kind == "cancel-tcpip-forward" {
			t.Fatalf("port forward request %s", kind)
		}
	}
}

func TestConnectWithoutFingerprintDoesNotDial(t *testing.T) {
	srv := startFake(t, "x", nil)
	host, port := srv.hostPort()
	_, err := Connect(context.Background(), Target{
		Host: host, Port: port, User: "root",
		Password: func() (string, error) { return "x", nil },
	})
	if !errors.Is(err, ErrBadTarget) {
		t.Fatal(err)
	}
	if srv.conns.Load() != 0 {
		t.Fatal("dialed without a fingerprint")
	}
}

func dialInteractive(t *testing.T, srv *fakeServer, target Target) *Terminal {
	t.Helper()
	marker := []byte("ping")
	if target.PrivateKey != nil {
		marker = []byte("key")
	}
	term, err := Connect(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { term.Close() })
	if _, err := term.Write(marker); err != nil {
		t.Fatal(err)
	}
	return term
}

func readSome(t *testing.T, term *Terminal) []byte {
	t.Helper()
	buf := make([]byte, 32)
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := term.Read(buf)
		ch <- result{n, err}
	}()
	select {
	case res := <-ch:
		if res.n == 0 && res.err != nil && !errors.Is(res.err, io.EOF) {
			t.Fatal(res.err)
		}
		return buf[:res.n]
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for terminal output")
		return nil
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}
