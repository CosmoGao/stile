package web_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/pem"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

type labSSH struct {
	ln       net.Listener
	cfg      *ssh.ServerConfig
	fp       string
	password string
	userKey  ssh.PublicKey

	passwordCalls atomic.Int32
	keyCalls      atomic.Int32
	conns         atomic.Int32
	closeAfter    atomic.Bool

	mu      sync.Mutex
	methods []string
	globals []string
}

func startLab(t *testing.T, password string, userKey ssh.PublicKey) *labSSH {
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
	s := &labSSH{ln: ln, fp: ssh.FingerprintSHA256(hostSigner.PublicKey()), password: password, userKey: userKey}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.passwordCalls.Add(1)
			if subtle.ConstantTimeCompare(pass, []byte(s.password)) == 1 {
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

func (s *labSSH) hostPort() (string, string) {
	host, port, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		return "", ""
	}
	return host, port
}

func (s *labSSH) serve(conn net.Conn) {
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
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for req := range requests {
				switch req.Type {
				case "pty-req":
					req.Reply(true, nil)
				case "shell":
					req.Reply(true, nil)
					go func() {
						buf := make([]byte, 1024)
						for {
							n, err := channel.Read(buf)
							if n > 0 {
								_, _ = channel.Write(buf[:n])
								if s.closeAfter.Load() {
									channel.Close()
									return
								}
							}
							if err != nil {
								return
							}
						}
					}()
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}()
	}
}

func (s *labSSH) methodsCopy() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.methods...)
}

func (s *labSSH) globalsCopy() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.globals...)
}

func TestWebSSH(t *testing.T) {
	const secret = "web-ssh-secret-pass-zz"
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
	lab := startLab(t, secret, userSigner.PublicKey())
	host, port := lab.hostPort()

	_, ts, dbPath := startServer(t, 3, time.Hour, 2*time.Hour)
	admin := newClient(t)
	createAdmin(t, admin, ts.URL, "admin", "admin-password")
	createUser(t, admin, ts.URL, "alice", "alice-password")
	createUser(t, admin, ts.URL, "erin", "erin-password")
	alice := newClient(t)
	if status, body := login(t, alice, ts.URL, "alice", "alice-password", ""); status != http.StatusSeeOther {
		t.Fatalf("alice login %d %s", status, body)
	}
	erin := newClient(t)
	if status, body := login(t, erin, ts.URL, "erin", "erin-password", ""); status != http.StatusSeeOther {
		t.Fatalf("erin login %d %s", status, body)
	}
	aliceID := userID(t, admin, ts.URL, "alice")
	erinID := userID(t, admin, ts.URL, "erin")
	db := openWriteDB(t, dbPath)

	passID := makePasswordCredential(t, admin, ts.URL, "ssh-pass", secret)
	badID := makePasswordCredential(t, admin, ts.URL, "ssh-bad", secret)
	keyID := makeKeyCredential(t, admin, ts.URL, "ssh-key", keyPEM)
	if _, err := db.Exec(`UPDATE credentials SET secret_ciphertext = ? WHERE id = ?`, bytes.Repeat([]byte{9}, 24), badID); err != nil {
		t.Fatal(err)
	}

	nofp := makeSSHAsset(t, admin, ts.URL, "nofp-box", host, port, passID, "")
	nocred := makeSSHAsset(t, admin, ts.URL, "nocred-box", host, port, "", "")
	mismatch := makeSSHAsset(t, admin, ts.URL, "badfp-box", host, port, badID, "SHA256:wrong-manual-fingerprint")
	good := makeSSHAsset(t, admin, ts.URL, "good-box", host, port, passID, "SHA256:old-manual-fingerprint")
	keyed := makeSSHAsset(t, admin, ts.URL, "key-box", host, port, keyID, "")
	rdp := makeProtocolAsset(t, admin, ts.URL, "rdp-box", "rdp", host, port, "")
	grantTo(t, admin, ts.URL, nofp, "user", aliceID)
	grantTo(t, admin, ts.URL, nocred, "user", aliceID)
	grantTo(t, admin, ts.URL, mismatch, "user", aliceID)
	grantTo(t, admin, ts.URL, good, "user", aliceID)
	grantTo(t, admin, ts.URL, keyed, "user", aliceID)
	grantTo(t, admin, ts.URL, rdp, "user", aliceID)
	grantTo(t, admin, ts.URL, good, "user", erinID)

	t.Run("refused", func(t *testing.T) {
		before := lab.conns.Load()
		status, body, _ := get(t, alice, ts.URL+"/assets/"+nofp+"/open")
		if status != http.StatusConflict || !strings.Contains(body, "还没有登记主机密钥指纹") || strings.Contains(body, "WebSocket") || strings.Contains(body, secret) {
			t.Fatalf("missing fingerprint page %d %s", status, body)
		}
		status, resp := dialStatus(t, ts.URL, alice, nofp)
		if status != http.StatusConflict || !strings.Contains(resp, "不连接") {
			t.Fatalf("missing fingerprint socket %d %s", status, resp)
		}
		status, body, _ = get(t, alice, ts.URL+"/assets/"+nocred+"/open")
		if status != http.StatusConflict || !strings.Contains(body, "未绑定凭据") || strings.Contains(body, "WebSocket") {
			t.Fatalf("missing credential page %d %s", status, body)
		}
		status, body, _ = get(t, admin, ts.URL+"/assets/"+good+"/open")
		if status != http.StatusForbidden || !strings.Contains(body, "没有授权，打不开") || strings.Contains(body, "good-box") || strings.Contains(body, secret) {
			t.Fatalf("admin without grant %d %s", status, body)
		}
		status, _ = dialStatus(t, ts.URL, admin, good)
		if status != http.StatusForbidden {
			t.Fatalf("admin socket %d", status)
		}
		status, body, _ = get(t, alice, ts.URL+"/assets/"+rdp+"/open")
		if status != http.StatusOK || !strings.Contains(body, "不连接 guacd") || strings.Contains(body, "WebSocket") {
			t.Fatalf("rdp open %d %s", status, body)
		}
		beforeRDP := lab.conns.Load()
		page := assetsPage(t, admin, ts.URL)
		status, body, _ = postForm(t, admin, ts.URL+"/admin/assets/"+rdp+"/probe", url.Values{"csrf": {mustCSRF(t, page)}})
		if status != http.StatusBadRequest || !strings.Contains(body, "只有 SSH") {
			t.Fatalf("rdp probe %d %s", status, body)
		}
		if lab.conns.Load() != beforeRDP {
			t.Fatal("rdp probe dialed")
		}
		status, _ = dialStatus(t, ts.URL, alice, rdp)
		if status != http.StatusForbidden {
			t.Fatalf("rdp socket %d", status)
		}
		anon := newClient(t)
		status, _ = dialStatus(t, ts.URL, anon, good)
		if status != http.StatusUnauthorized {
			t.Fatalf("anonymous socket %d", status)
		}
		if lab.conns.Load() != before {
			t.Fatalf("refused paths dialed, conns %d -> %d", before, lab.conns.Load())
		}
		if n := sessionRows(t, db); n != 0 {
			t.Fatalf("failed opens wrote %d session rows", n)
		}
	})

	t.Run("probe and overwrite", func(t *testing.T) {
		before := lab.conns.Load()
		calls := lab.passwordCalls.Load()
		page := assetsPage(t, admin, ts.URL)
		status, body, _ := postForm(t, admin, ts.URL+"/admin/assets/"+nocred+"/probe", url.Values{"csrf": {mustCSRF(t, page)}})
		body = html.UnescapeString(body)
		if status != http.StatusOK || !strings.Contains(body, lab.fp) {
			t.Fatalf("probe without credential %d %s", status, body)
		}
		if got := storedFingerprint(t, db, nocred); got != "" {
			t.Fatalf("probe saved fingerprint %q", got)
		}
		if lab.passwordCalls.Load() != calls || len(lab.methodsCopy()) != 0 {
			t.Fatalf("probe authenticated methods=%v calls=%d", lab.methodsCopy(), lab.passwordCalls.Load())
		}
		if lab.conns.Load() <= before {
			t.Fatal("probe did not connect")
		}
		confirmHostKey(t, admin, ts.URL, nocred, body)
		if got := storedFingerprint(t, db, nocred); got != lab.fp {
			t.Fatalf("confirmed fingerprint %q", got)
		}
		page = assetsPage(t, admin, ts.URL)
		status, body, _ = postForm(t, admin, ts.URL+"/admin/assets/"+good+"/probe", url.Values{"csrf": {mustCSRF(t, page)}})
		body = html.UnescapeString(body)
		if status != http.StatusOK || !strings.Contains(body, lab.fp) {
			t.Fatalf("probe existing fingerprint %d %s", status, body)
		}
		if got := storedFingerprint(t, db, good); got != "SHA256:old-manual-fingerprint" {
			t.Fatalf("probe overwrote before confirm: %q", got)
		}
		confirmHostKey(t, admin, ts.URL, good, body)
		if got := storedFingerprint(t, db, good); got != lab.fp {
			t.Fatalf("overwrite fingerprint %q", got)
		}
		status, _, _ = postForm(t, alice, ts.URL+"/admin/assets/"+good+"/probe", url.Values{"csrf": {mustCSRF(t, visiblePage(t, alice, ts.URL))}})
		if status != http.StatusForbidden {
			t.Fatalf("alice probe %d", status)
		}
		if n := sessionRows(t, db); n != 0 {
			t.Fatalf("probe wrote %d session rows", n)
		}
	})

	t.Run("fingerprint mismatch", func(t *testing.T) {
		before := lab.conns.Load()
		calls := lab.passwordCalls.Load()
		status, body, _ := get(t, alice, ts.URL+"/assets/"+mismatch+"/open")
		if status != http.StatusOK || !strings.Contains(body, "/static/xterm.js") || strings.Contains(body, secret) || strings.Contains(body, "PRIVATE KEY") {
			t.Fatalf("mismatch page %d", status)
		}
		status, resp := dialStatus(t, ts.URL, alice, mismatch)
		if status != http.StatusForbidden || !strings.Contains(resp, "主机密钥不符") {
			t.Fatalf("mismatch socket %d %s", status, resp)
		}
		if lab.conns.Load() <= before {
			t.Fatal("mismatch did not connect for key exchange")
		}
		if lab.passwordCalls.Load() != calls || len(lab.methodsCopy()) != 0 {
			t.Fatalf("mismatch sent auth calls=%d methods=%v", lab.passwordCalls.Load(), lab.methodsCopy())
		}
		if n := sessionRows(t, db); n != 0 {
			t.Fatalf("mismatch wrote %d rows", n)
		}
	})

	t.Run("interactive", func(t *testing.T) {
		status, body, _ := get(t, alice, ts.URL+"/assets/"+good+"/open")
		if status != http.StatusOK {
			t.Fatalf("open %d %s", status, body)
		}
		for _, want := range []string{"/static/xterm.js", "/static/xterm.css", "/static/xterm-addon-fit.js", "WebSocket", "/ssh"} {
			if !strings.Contains(body, want) {
				t.Fatalf("terminal page missing %s", want)
			}
		}
		for _, banned := range []string{secret, "PRIVATE KEY", "断开", "会话列表", sessionCookieValue(t, alice, ts.URL), passID} {
			if strings.Contains(body, banned) {
				t.Fatalf("terminal page contains %q", banned)
			}
		}
		if strings.Contains(body, "stile_session=") {
			t.Fatal("session token is in the page")
		}
		conn := dialOK(t, ts.URL, alice, good)
		writeWS(t, conn, "abc")
		got := readWS(t, conn, "abc")
		if string(got) != "abc" {
			t.Fatalf("echo %q", got)
		}
		conn.Close(websocket.StatusNormalClosure, "")
		user, assetID, started, ended := waitSession(t, db, good, aliceID)
		if user != aliceID || assetID != good || started == "" || ended == "" {
			t.Fatalf("log %s %s %s %s", user, assetID, started, ended)
		}
		if strings.Contains(started+ended, "abc") || strings.Contains(started+ended, secret) {
			t.Fatal("log contains terminal data or the secret")
		}
		assertSessionShape(t, db)

		lab.closeAfter.Store(true)
		defer lab.closeAfter.Store(false)
		conn = dialOK(t, ts.URL, alice, good)
		writeWS(t, conn, "xyz")
		deadline := time.Now().Add(3 * time.Second)
		var n int
		for {
			if err := db.QueryRow(`SELECT COUNT(*) FROM web_sessions WHERE asset_id = ? AND ended_at IS NOT NULL`, good).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n >= 2 || time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		conn.Close(websocket.StatusNormalClosure, "")
		if n < 2 {
			t.Fatalf("remote close rows %d", n)
		}
		for _, kind := range lab.globalsCopy() {
			if kind == "tcpip-forward" {
				t.Fatal("requested port forwarding")
			}
		}
	})

	t.Run("private key", func(t *testing.T) {
		page := assetsPage(t, admin, ts.URL)
		status, body, res := postForm(t, admin, ts.URL+"/admin/assets/"+keyed+"/hostkey", url.Values{
			"csrf":                     {mustCSRF(t, page)},
			"ssh_host_key_fingerprint": {lab.fp},
		})
		if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=hostkey-saved") {
			t.Fatalf("save key asset fingerprint %d %s", status, body)
		}
		status, body, _ = get(t, alice, ts.URL+"/assets/"+keyed+"/open")
		if status != http.StatusOK || strings.Contains(body, "PRIVATE KEY") || strings.Contains(body, keyPEM) || strings.Contains(body, secret) {
			t.Fatalf("key page exposes a secret, status %d", status)
		}
		before := lab.keyCalls.Load()
		conn := dialOK(t, ts.URL, alice, keyed)
		writeWS(t, conn, "key")
		if string(readWS(t, conn, "key")) != "key" {
			t.Fatal("key session did not echo")
		}
		conn.Close(websocket.StatusNormalClosure, "")
		if lab.keyCalls.Load() <= before {
			t.Fatal("private key was not used")
		}
		waitSession(t, db, keyed, aliceID)
	})

	t.Run("locked and disabled", func(t *testing.T) {
		before := lab.conns.Load()
		until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
		if _, err := db.Exec(`UPDATE users SET locked_until = ? WHERE id = ?`, until, erinID); err != nil {
			t.Fatal(err)
		}
		status, _ := dialStatus(t, ts.URL, erin, good)
		if status != http.StatusUnauthorized {
			t.Fatalf("locked socket %d", status)
		}
		if _, err := db.Exec(`UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?`, erinID); err != nil {
			t.Fatal(err)
		}
		erin2 := newClient(t)
		if status, body := login(t, erin2, ts.URL, "erin", "erin-password", ""); status != http.StatusSeeOther {
			t.Fatalf("erin relogin %d %s", status, body)
		}
		disableUser(t, admin, ts.URL, erinID)
		status, _ = dialStatus(t, ts.URL, erin2, good)
		if status != http.StatusUnauthorized {
			t.Fatalf("disabled socket %d", status)
		}
		if lab.conns.Load() != before {
			t.Fatal("locked or disabled user was dialed")
		}
	})

	t.Run("no session list", func(t *testing.T) {
		for _, path := range []string{"/admin/sessions", "/sessions", "/assets/sessions"} {
			status, body, _ := get(t, admin, ts.URL+path)
			if status != http.StatusNotFound && status != http.StatusUnauthorized {
				t.Fatalf("%s -> %d %s", path, status, body)
			}
		}
		status, body, _ := get(t, admin, ts.URL+"/static/xterm.js")
		if status != http.StatusOK || !strings.Contains(body, "Terminal") || strings.Contains(body, secret) {
			t.Fatalf("xterm.js %d", status)
		}
		status, body, _ = get(t, nilClient(t), ts.URL+"/healthz")
		if status != http.StatusOK || body != "ok" {
			t.Fatalf("healthz %d %s", status, body)
		}
	})
}

func openWriteDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func nilClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func makePasswordCredential(t *testing.T, c *http.Client, base, name, secret string) string {
	t.Helper()
	page := credentialsPage(t, c, base)
	status, body, _ := postForm(t, c, base+"/admin/credentials", url.Values{
		"csrf":       {mustCSRF(t, page)},
		"name":       {name},
		"kind":       {"password"},
		"login_name": {"root"},
		"secret":     {secret},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("credential %s %d %s", name, status, body)
	}
	return credentialID(t, credentialsPage(t, c, base), name, "password", "root", "")
}

func makeKeyCredential(t *testing.T, c *http.Client, base, name, pemText string) string {
	t.Helper()
	page := credentialsPage(t, c, base)
	status, body, _ := postForm(t, c, base+"/admin/credentials", url.Values{
		"csrf":       {mustCSRF(t, page)},
		"name":       {name},
		"kind":       {"ssh_private_key"},
		"login_name": {"root"},
		"secret":     {pemText},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("key credential %d %s", status, body)
	}
	list := credentialsPage(t, c, base)
	if strings.Contains(list, pemText) || strings.Contains(list, "PRIVATE KEY") {
		t.Fatal("credential list contains the private key")
	}
	re := regexp.MustCompile(`data-credential-id="([0-9a-f-]+)" data-name="` + regexp.QuoteMeta(name) + `" data-kind="ssh_private_key"`)
	m := re.FindStringSubmatch(list)
	if m == nil {
		t.Fatalf("key credential not listed: %s", list)
	}
	return m[1]
}

func makeSSHAsset(t *testing.T, c *http.Client, base, name, host, port, credID, fp string) string {
	t.Helper()
	return makeProtocolAsset(t, c, base, name, "ssh", host, port, credID, fp)
}

func makeProtocolAsset(t *testing.T, c *http.Client, base, name, protocol, host, port, credID string, extra ...string) string {
	t.Helper()
	fp := ""
	if len(extra) > 0 {
		fp = extra[0]
	}
	page := assetsPage(t, c, base)
	status, body, res := postForm(t, c, base+"/admin/assets", url.Values{
		"csrf":                     {mustCSRF(t, page)},
		"name":                     {name},
		"protocol":                 {protocol},
		"host":                     {host},
		"port":                     {port},
		"credential_id":            {credID},
		"ssh_host_key_fingerprint": {fp},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=asset-saved") {
		t.Fatalf("asset %s %d %s", name, status, body)
	}
	id, _, _, _ := assetRow(t, assetsPage(t, c, base), name, protocol, host)
	return id
}

func confirmHostKey(t *testing.T, c *http.Client, base, assetID, probePage string) {
	t.Helper()
	re := regexp.MustCompile(`id="probed-fingerprint">([^<]+)<`)
	m := re.FindStringSubmatch(probePage)
	if m == nil {
		t.Fatalf("probe page has no fingerprint: %s", probePage)
	}
	status, body, res := postForm(t, c, base+"/admin/assets/"+assetID+"/hostkey", url.Values{
		"csrf":                     {mustCSRF(t, probePage)},
		"ssh_host_key_fingerprint": {m[1]},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=hostkey-saved") {
		t.Fatalf("confirm fingerprint %d %s", status, body)
	}
}

func storedFingerprint(t *testing.T, db *sql.DB, assetID string) string {
	t.Helper()
	var fp sql.NullString
	if err := db.QueryRow(`SELECT ssh_host_key_fingerprint FROM assets WHERE id = ?`, assetID).Scan(&fp); err != nil {
		t.Fatal(err)
	}
	if !fp.Valid {
		return ""
	}
	return fp.String
}

func sessionRows(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM web_sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func cookieHeader(c *http.Client, base string) string {
	u, _ := url.Parse(base + "/")
	if c.Jar == nil {
		return ""
	}
	var parts []string
	for _, ck := range c.Jar.Cookies(u) {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

func sessionCookieValue(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	u, _ := url.Parse(base + "/")
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "stile_session" && ck.Value != "" {
			return ck.Value
		}
	}
	t.Fatal("missing session cookie")
	return ""
}

func dialStatus(t *testing.T, base string, c *http.Client, assetID string) (int, string) {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(base, "http") + "/assets/" + assetID + "/ssh"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Cookie": {cookieHeader(c, base)}},
	})
	if conn != nil {
		conn.Close(websocket.StatusNormalClosure, "")
	}
	if resp == nil {
		t.Fatalf("dial %s: %v", assetID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("dial %s succeeded, status %d", assetID, resp.StatusCode)
	}
	return resp.StatusCode, string(body)
}

func dialOK(t *testing.T, base string, c *http.Client, assetID string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(base, "http") + "/assets/" + assetID + "/ssh"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Cookie": {cookieHeader(c, base)}},
	})
	if err != nil {
		if resp != nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("dial %s: %v %s", assetID, err, b)
		}
		t.Fatal(err)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	t.Cleanup(func() { conn.Close(websocket.StatusNormalClosure, "") })
	return conn
}

func writeWS(t *testing.T, conn *websocket.Conn, text string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageBinary, []byte(text)); err != nil {
		t.Fatal(err)
	}
}

func readWS(t *testing.T, conn *websocket.Conn, want string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var got []byte
	for !bytes.Contains(got, []byte(want)) {
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v got %q", err, got)
		}
		got = append(got, data...)
	}
	return got
}

func waitSession(t *testing.T, db *sql.DB, assetID, userID string) (string, string, string, string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var user, asset, started string
		var ended sql.NullString
		err := db.QueryRow(`SELECT user_id, asset_id, started_at, ended_at FROM web_sessions WHERE asset_id = ? AND user_id = ? ORDER BY started_at DESC LIMIT 1`, assetID, userID).Scan(&user, &asset, &started, &ended)
		if err == nil && ended.Valid && ended.String != "" {
			return user, asset, started, ended.String
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("session for %s did not end", assetID)
	return "", "", "", ""
}

func assertSessionShape(t *testing.T, db *sql.DB) {
	t.Helper()
	var create string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE name = 'web_sessions'`).Scan(&create); err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(create)
	for _, bad := range []string{"command", "output", "record", "client", "addr", "bytes", "password"} {
		if strings.Contains(lower, bad) {
			t.Fatalf("web_sessions schema contains %s: %s", bad, create)
		}
	}
	cols := tableColumns(t, db, "web_sessions")
	if len(cols) != 5 || !cols["id"] || !cols["user_id"] || !cols["asset_id"] || !cols["started_at"] || !cols["ended_at"] {
		t.Fatalf("columns %v", cols)
	}
	var names []string
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%login%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if len(names) != 1 || names[0] != "login_tokens" {
		t.Fatalf("login tables %v", names)
	}
}
