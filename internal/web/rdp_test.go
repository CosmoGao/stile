package web_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/CosmoGao/stile/internal/rdpproxy"
)

func TestWebRDP(t *testing.T) {
	const secret = "p,a;ss词-9f3c"
	fake := startFakeGuacd(t)
	srv, ts, dbPath := startServer(t, 3, time.Hour, 2*time.Hour)
	srv.SetGuacdAddress(fake.addr())
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

	passID := makeLoginCredential(t, admin, ts.URL, "rdp-pass", "rdp-user", secret)
	keyID := makeKeyCredential(t, admin, ts.URL, "rdp-key", testPEM(t))
	if _, err := db.Exec(`UPDATE credentials SET secret_ciphertext = ? WHERE id = ?`, bytes.Repeat([]byte{7}, 24), keyID); err != nil {
		t.Fatal(err)
	}
	granted := makeProtocolAsset(t, admin, ts.URL, "win-ok", "rdp", "198.51.100.40", "3391", passID)
	keyed := makeProtocolAsset(t, admin, ts.URL, "win-key", "rdp", "198.51.100.41", "3392", keyID)
	bare := makeProtocolAsset(t, admin, ts.URL, "win-bare", "rdp", "198.51.100.42", "3393", "")
	hidden := makeProtocolAsset(t, admin, ts.URL, "win-hidden", "rdp", "198.51.100.43", "3394", passID)
	sshAsset := makeSSHAsset(t, admin, ts.URL, "linux-box", "198.51.100.44", "22", passID, "SHA256:not-used-here")
	grantTo(t, admin, ts.URL, granted, "user", aliceID)
	grantTo(t, admin, ts.URL, keyed, "user", aliceID)
	grantTo(t, admin, ts.URL, bare, "user", aliceID)
	grantTo(t, admin, ts.URL, sshAsset, "user", aliceID)
	groups := groupsPage(t, admin, ts.URL)
	status, body, _ := postForm(t, admin, ts.URL+"/admin/groups", url.Values{
		"csrf": {mustCSRF(t, groups)},
		"name": {"rdp-ops"},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("group %d %s", status, body)
	}
	group := groupID(t, groupsPage(t, admin, ts.URL), "rdp-ops")
	addMember(t, admin, ts.URL, group, erinID)
	grantTo(t, admin, ts.URL, granted, "group", group)

	t.Run("refused", func(t *testing.T) {
		before := fake.conns.Load()
		status, body, _ := get(t, admin, ts.URL+"/assets/"+granted+"/open")
		if status != http.StatusForbidden || !strings.Contains(body, "没有授权，打不开") || strings.Contains(body, secret) || strings.Contains(body, "guacamole") {
			t.Fatalf("admin page %d %s", status, body)
		}
		status, text := dialRDPStatus(t, ts.URL, admin, granted)
		if status != http.StatusForbidden {
			t.Fatalf("admin socket %d %s", status, text)
		}
		status, body, _ = get(t, alice, ts.URL+"/assets/"+hidden+"/open")
		if status != http.StatusForbidden || strings.Contains(body, "win-hidden") || strings.Contains(body, secret) {
			t.Fatalf("hidden page %d %s", status, body)
		}
		status, _ = dialRDPStatus(t, ts.URL, alice, hidden)
		if status != http.StatusForbidden {
			t.Fatalf("hidden socket %d", status)
		}
		status, body, _ = get(t, alice, ts.URL+"/assets/"+keyed+"/open")
		if status != http.StatusConflict || !strings.Contains(body, "凭据必须是密码") || strings.Contains(body, secret) || strings.Contains(body, "guacamole") || strings.Contains(body, "PRIVATE") {
			t.Fatalf("key page %d %s", status, body)
		}
		status, text = dialRDPStatus(t, ts.URL, alice, keyed)
		if status != http.StatusConflict || !strings.Contains(text, "凭据必须是密码") {
			t.Fatalf("key socket %d %s", status, text)
		}
		status, body, _ = get(t, alice, ts.URL+"/assets/"+bare+"/open")
		if status != http.StatusConflict || !strings.Contains(body, "未绑定凭据") || strings.Contains(body, "guacamole") {
			t.Fatalf("bare page %d %s", status, body)
		}
		status, _ = dialRDPStatus(t, ts.URL, alice, sshAsset)
		if status != http.StatusForbidden {
			t.Fatalf("ssh on rdp socket %d", status)
		}
		anon := newClient(t)
		status, _ = dialRDPStatus(t, ts.URL, anon, granted)
		if status != http.StatusUnauthorized {
			t.Fatalf("anonymous %d", status)
		}
		if fake.conns.Load() != before {
			t.Fatalf("refused paths dialed guacd: %d -> %d", before, fake.conns.Load())
		}
		if n := sessionRows(t, db); n != 0 {
			t.Fatalf("failed opens wrote %d rows", n)
		}
	})

	t.Run("password filled", func(t *testing.T) {
		before := fake.conns.Load()
		status, body, _ := get(t, alice, ts.URL+"/assets/"+granted+"/open")
		cookie := sessionCookieValue(t, alice, ts.URL)
		if status != http.StatusOK || !strings.Contains(body, "/static/guacamole-common.js") || !strings.Contains(body, "/rdp") {
			t.Fatalf("page %d %s", status, body)
		}
		if strings.Contains(body, secret) || strings.Contains(body, cookie) || strings.Contains(body, "断开") || strings.Contains(body, "会话列表") {
			t.Fatal("rdp page contains a secret, the cookie, a disconnect control, or a session list")
		}
		if strings.Contains(body, "rdp-user") {
			t.Fatal("login name is on the rdp page")
		}
		jsStatus, jsBody, _ := get(t, alice, ts.URL+"/static/guacamole-common.js")
		if jsStatus != http.StatusOK || !strings.Contains(jsBody, "Guacamole.Client") || strings.Contains(jsBody, secret) {
			t.Fatalf("library %d", jsStatus)
		}
		conn := dialRDP(t, ts.URL, alice, granted)
		readUntil(t, conn, "0.")
		ping := "0.,4.ping,1.9;"
		writeText(t, conn, ping)
		readUntil(t, conn, ping)
		if fake.conns.Load() != before+1 {
			t.Fatalf("dials %d -> %d", before, fake.conns.Load())
		}
		filled := fake.last()
		if filled["hostname"] != "198.51.100.40" || filled["port"] != "3391" || filled["username"] != "rdp-user" || filled["password"] != secret {
			t.Fatalf("filled host=%q port=%q user=%q password ok=%v", filled["hostname"], filled["port"], filled["username"], filled["password"] == secret)
		}
		if filled["enable-drive"] != "false" || filled["drive-name"] != "" || filled["drive-path"] != "" || filled["create-drive-path"] != "false" {
			t.Fatalf("drive %#v", filled)
		}
		if filled["disable-download"] != "true" || filled["disable-upload"] != "true" || filled["enable-sftp"] != "false" || filled["enable-printing"] != "false" {
			t.Fatalf("transfer %#v", filled)
		}
		if filled["recording-path"] != "" || filled["create-recording-path"] != "false" {
			t.Fatalf("recording %#v", filled)
		}
		for _, op := range fake.afterOps() {
			if op == "" || op == "ping" {
				t.Fatalf("forwarded tunnel ping: %q", op)
			}
		}
		var started string
		var ended sql.NullString
		if err := db.QueryRow(`SELECT started_at, ended_at FROM web_sessions WHERE asset_id = ? AND user_id = ?`, granted, aliceID).Scan(&started, &ended); err != nil {
			t.Fatal(err)
		}
		if started == "" || ended.Valid {
			t.Fatalf("open session started=%q ended=%v", started, ended)
		}
		conn.Close(websocket.StatusNormalClosure, "")
		user, asset, start, end := waitSession(t, db, granted, aliceID)
		if user != aliceID || asset != granted || start == "" || end == "" {
			t.Fatalf("session %s %s %s %s", user, asset, start, end)
		}
		assertSessionShape(t, db)
	})

	t.Run("group grant", func(t *testing.T) {
		before := fake.conns.Load()
		conn := dialRDP(t, ts.URL, erin, granted)
		readUntil(t, conn, "0.")
		if fake.conns.Load() != before+1 {
			t.Fatalf("group grant did not dial")
		}
		filled := fake.last()
		if filled["password"] != secret || filled["hostname"] != "198.51.100.40" {
			t.Fatal("group grant fill mismatch")
		}
		conn.Close(websocket.StatusNormalClosure, "")
		waitSession(t, db, granted, erinID)
	})

	t.Run("handshake failure writes nothing", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		srv.SetGuacdAddress(ln.Addr().String())
		before := sessionRows(t, db)
		status, _ := dialRDPStatus(t, ts.URL, alice, granted)
		if status != http.StatusBadGateway {
			t.Fatalf("status %d", status)
		}
		if sessionRows(t, db) != before {
			t.Fatal("failed handshake wrote a session")
		}
	})

	t.Run("ssh still works when guacd is down", func(t *testing.T) {
		closed, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		closedAddr := closed.Addr().String()
		closed.Close()
		srv.SetGuacdAddress(closedAddr)
		lab := startLab(t, secret, nil)
		host, port := lab.hostPort()
		good := makeSSHAsset(t, admin, ts.URL, "ssh-while-down", host, port, passID, "")
		page := assetsPage(t, admin, ts.URL)
		status, body, _ := postForm(t, admin, ts.URL+"/admin/assets/"+good+"/probe", url.Values{"csrf": {mustCSRF(t, page)}})
		body = html.UnescapeString(body)
		if status != http.StatusOK || !strings.Contains(body, lab.fp) {
			t.Fatalf("probe %d %s", status, body)
		}
		confirmHostKey(t, admin, ts.URL, good, body)
		grantTo(t, admin, ts.URL, good, "user", aliceID)
		before := lab.conns.Load()
		rows := sessionRows(t, db)
		conn := dialOK(t, ts.URL, alice, good)
		writeWS(t, conn, "hi")
		readWS(t, conn, "hi")
		if lab.conns.Load() <= before {
			t.Fatal("ssh did not connect")
		}
		status, _ = dialRDPStatus(t, ts.URL, alice, granted)
		if status != http.StatusBadGateway {
			t.Fatalf("rdp while guacd down %d", status)
		}
		conn.Close(websocket.StatusNormalClosure, "")
		waitSession(t, db, good, aliceID)
		if sessionRows(t, db) != rows+1 {
			t.Fatalf("rows %d -> %d", rows, sessionRows(t, db))
		}
	})
}

func testPEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

func makeLoginCredential(t *testing.T, c *http.Client, base, name, login, secret string) string {
	t.Helper()
	page := credentialsPage(t, c, base)
	status, body, _ := postForm(t, c, base+"/admin/credentials", url.Values{
		"csrf":       {mustCSRF(t, page)},
		"name":       {name},
		"kind":       {"password"},
		"login_name": {login},
		"secret":     {secret},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("credential %s %d %s", name, status, body)
	}
	return credentialID(t, credentialsPage(t, c, base), name, "password", login, "")
}

type fakeGuacd struct {
	ln     net.Listener
	conns  atomic.Int32
	mu     sync.Mutex
	filled map[string]string
	after  []string
}

func startFakeGuacd(t *testing.T) *fakeGuacd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGuacd{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeGuacd) addr() string { return f.ln.Addr().String() }

func (f *fakeGuacd) last() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.filled {
		out[k] = v
	}
	return out
}

func (f *fakeGuacd) afterOps() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.after...)
}

func (f *fakeGuacd) serve(conn net.Conn) {
	f.conns.Add(1)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	rd := rdpproxy.NewReader(conn)
	op, args, _, err := rd.Next()
	if err != nil || op != "select" || len(args) != 1 || args[0] != "rdp" {
		return
	}
	names := []string{
		"hostname", "port", "username", "password",
		"enable-drive", "drive-name", "drive-path", "create-drive-path",
		"disable-download", "disable-upload", "enable-printing", "enable-sftp",
		"recording-path", "recording-name", "create-recording-path",
	}
	if _, err := conn.Write(rdpproxy.Encode("args", names...)); err != nil {
		return
	}
	var connect []string
	for {
		op, args, _, err = rd.Next()
		if err != nil {
			return
		}
		if op == "connect" {
			connect = args
			break
		}
	}
	filled := map[string]string{}
	if len(connect) == len(names)+1 {
		for i, name := range names {
			filled[name] = connect[i+1]
		}
	}
	f.mu.Lock()
	f.filled = filled
	f.mu.Unlock()
	if _, err := conn.Write(rdpproxy.Encode("ready", "c1")); err != nil {
		return
	}
	if _, err := conn.Write(rdpproxy.Encode("nop")); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	for {
		op, _, _, err = rd.Next()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.after = append(f.after, op)
		f.mu.Unlock()
	}
}

func dialRDP(t *testing.T, base string, c *http.Client, assetID string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(base, "http") + "/assets/" + assetID + "/rdp"
	if strings.Contains(wsURL, "password") {
		t.Fatal("rdp url contains password")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"guacamole"},
		HTTPHeader:   http.Header{"Cookie": {cookieHeader(c, base)}},
	})
	if err != nil {
		if resp != nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("dial rdp %s: %v %s", assetID, err, b)
		}
		t.Fatal(err)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	t.Cleanup(func() { conn.Close(websocket.StatusNormalClosure, "") })
	return conn
}

func dialRDPStatus(t *testing.T, base string, c *http.Client, assetID string) (int, string) {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(base, "http") + "/assets/" + assetID + "/rdp"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"guacamole"},
		HTTPHeader:   http.Header{"Cookie": {cookieHeader(c, base)}},
	})
	if conn != nil {
		conn.Close(websocket.StatusNormalClosure, "")
	}
	if resp == nil {
		t.Fatalf("dial rdp %s: %v", assetID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("dial rdp %s succeeded, status %d", assetID, resp.StatusCode)
	}
	return resp.StatusCode, string(body)
}

func readUntil(t *testing.T, conn *websocket.Conn, want string) {
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
}

func writeText(t *testing.T, conn *websocket.Conn, text string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte(text)); err != nil {
		t.Fatal(err)
	}
}
