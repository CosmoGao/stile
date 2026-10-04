package web_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CosmoGao/stile/internal/config"
	"github.com/CosmoGao/stile/internal/store"
	"github.com/CosmoGao/stile/internal/web"
	"github.com/pquerna/otp/totp"

	_ "modernc.org/sqlite"
)

func TestHealthz(t *testing.T) {
	_, ts, _ := startServer(t, 3, time.Hour, 2*time.Hour)
	res, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res)
	if res.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("healthz %d %q", res.StatusCode, body)
	}
}

func TestSetupThenClosed(t *testing.T) {
	_, ts, dbPath := startServer(t, 3, time.Hour, 2*time.Hour)
	c := newClient(t)
	status, _, res := get(t, c, ts.URL+"/")
	if status != http.StatusSeeOther || res.Header.Get("Location") != "/setup" {
		t.Fatalf("empty library redirect %d %s", status, res.Header.Get("Location"))
	}
	status, body, _ := get(t, c, ts.URL+"/setup")
	if status != http.StatusOK || !strings.Contains(body, "创建第一个管理员") {
		t.Fatalf("setup page %d %s", status, body)
	}
	status, _, res = postForm(t, c, ts.URL+"/setup", url.Values{
		"csrf":     {mustCSRF(t, body)},
		"username": {"admin"},
		"password": {"admin-password"},
	})
	if status != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("setup result %d %s", status, res.Header.Get("Location"))
	}
	var session *http.Cookie
	for _, ck := range res.Cookies() {
		if ck.Name == "stile_session" {
			session = ck
		}
	}
	if session == nil || !session.HttpOnly {
		t.Fatal("session cookie is missing or not HttpOnly")
	}
	if session.Secure {
		t.Fatal("secure flag would drop the cookie on plain HTTP")
	}
	raw, err := base64.RawURLEncoding.DecodeString(session.Value)
	if err != nil || len(raw) != 32 || strings.Contains(session.Value, ".") {
		t.Fatalf("session cookie is not an opaque 32-byte token: %q", session.Value)
	}
	status, body, _ = get(t, c, ts.URL+"/")
	if status != http.StatusOK || !strings.Contains(body, "已登录：admin") {
		t.Fatalf("home %d %s", status, body)
	}
	status, body, _ = get(t, c, ts.URL+"/setup")
	if status != http.StatusNotFound {
		t.Fatalf("setup still open: %d %s", status, body)
	}
	status, _, _ = postForm(t, c, ts.URL+"/setup", url.Values{
		"username": {"other"},
		"password": {"other-password"},
	})
	if status != http.StatusNotFound {
		t.Fatalf("second setup status %d", status)
	}

	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])
	db := openDB(t, dbPath)
	var stored string
	if err := db.QueryRow(`SELECT token_hash FROM login_tokens`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != want {
		t.Fatalf("stored %s want %s", stored, want)
	}
	if strings.Contains(stored, session.Value) {
		t.Fatal("database stores the raw cookie")
	}
	cols := tableColumns(t, db, "login_tokens")
	for _, banned := range []string{"token", "cookie", "jwt"} {
		if cols[banned] {
			t.Fatalf("login_tokens has %s", banned)
		}
	}
	if !cols["token_hash"] {
		t.Fatal("missing token_hash")
	}
}

func TestWrongPasswordDoesNotLoginAndNoLoginLog(t *testing.T) {
	_, ts, dbPath := startServer(t, 4, time.Hour, 2*time.Hour)
	admin := newClient(t)
	createAdmin(t, admin, ts.URL, "admin", "admin-password")

	c := newClient(t)
	status, body := login(t, c, ts.URL, "admin", "wrong-password", "")
	if status != http.StatusUnauthorized || !strings.Contains(body, "账号或口令不正确") {
		t.Fatalf("wrong password %d %s", status, body)
	}
	if strings.Contains(body, "已登录：") {
		t.Fatal("wrong password rendered a session")
	}
	status, body = login(t, c, ts.URL, "missing-user", "wrong-password", "")
	if status != http.StatusUnauthorized || !strings.Contains(body, "账号或口令不正确") {
		t.Fatalf("unknown user %d %s", status, body)
	}
	status, _, res := get(t, c, ts.URL+"/")
	if status != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
		t.Fatalf("anonymous home %d %s", status, res.Header.Get("Location"))
	}

	db := openDB(t, dbPath)
	names := tableNames(t, db)
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	allowed := map[string]bool{"users": true, "login_tokens": true, "schema_migrations": true}
	if len(got) != len(allowed) {
		t.Fatalf("tables = %v", names)
	}
	for n := range got {
		if !allowed[n] {
			t.Fatalf("unexpected table %s", n)
		}
	}
	var tokens int
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_tokens`).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	// The admin created above is still logged in on the other client.
	if tokens != 1 {
		t.Fatalf("token rows = %d, want the admin session only", tokens)
	}
	var attempts int
	var hash string
	if err := db.QueryRow(`SELECT failed_attempts, password_hash FROM users WHERE username = 'admin'`).Scan(&attempts, &hash); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("failed_attempts = %d", attempts)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("password hash %s", hash)
	}
}

func TestLockoutFollowsConfig(t *testing.T) {
	srv, ts, dbPath := startServer(t, 3, 45*time.Second, 2*time.Hour)
	clk := &manualClock{t: time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC)}
	srv.SetClock(clk.Now)
	admin := newClient(t)
	createAdmin(t, admin, ts.URL, "admin", "admin-password")
	createUser(t, admin, ts.URL, "alice", "alice-password")

	alice := newClient(t)
	status, _ := login(t, alice, ts.URL, "alice", "wrong-password", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("first miss %d", status)
	}
	status, body := login(t, alice, ts.URL, "alice", "wrong-password", "")
	if status != http.StatusUnauthorized || strings.Contains(body, "账号暂时不能登录") {
		t.Fatalf("two misses locked early: %d %s", status, body)
	}
	status, _ = login(t, alice, ts.URL, "alice", "alice-password", "")
	if status != http.StatusSeeOther {
		t.Fatalf("login before threshold: %d", status)
	}
	saved := sessionValue(t, alice, ts.URL)
	// Failures come from another client so the saved cookie stays in the jar
	// until lockout deletes it.
	other := newClient(t)
	for i := 0; i < 3; i++ {
		status, body = login(t, other, ts.URL, "alice", "wrong-password", "")
	}
	if status != http.StatusUnauthorized || !strings.Contains(body, "账号暂时不能登录") {
		t.Fatalf("third miss %d %s", status, body)
	}
	status, body = login(t, alice, ts.URL, "alice", "alice-password", "")
	if status != http.StatusUnauthorized || !strings.Contains(body, "账号暂时不能登录") {
		t.Fatalf("locked login %d %s", status, body)
	}
	replay(t, ts.URL, saved)

	db := openDB(t, dbPath)
	id := userID(t, admin, ts.URL, "alice")
	var tokens int
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_tokens WHERE user_id = ?`, id).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatalf("tokens after lock = %d", tokens)
	}

	clk.Advance(44 * time.Second)
	status, body = login(t, alice, ts.URL, "alice", "alice-password", "")
	if !strings.Contains(body, "账号暂时不能登录") {
		t.Fatalf("still inside configured duration: %d %s", status, body)
	}
	clk.Advance(time.Second)
	status, _ = login(t, alice, ts.URL, "alice", "alice-password", "")
	if status != http.StatusSeeOther {
		t.Fatalf("after configured duration: %d", status)
	}

	// A different threshold must lock on that count, not on the count used above.
	_, ts2, _ := startServer(t, 2, time.Hour, time.Hour)
	admin2 := newClient(t)
	createAdmin(t, admin2, ts2.URL, "admin", "admin-password")
	createUser(t, admin2, ts2.URL, "alice", "alice-password")
	bob := newClient(t)
	status, body = login(t, bob, ts2.URL, "alice", "wrong-password", "")
	if strings.Contains(body, "账号暂时不能登录") {
		t.Fatal("locked before the configured count")
	}
	status, _ = login(t, bob, ts2.URL, "alice", "alice-password", "")
	if status != http.StatusSeeOther {
		t.Fatalf("success under the other threshold: %d", status)
	}
	logout(t, bob, ts2.URL)
	_, _ = login(t, bob, ts2.URL, "alice", "wrong-password", "")
	status, body = login(t, bob, ts2.URL, "alice", "wrong-password", "")
	if !strings.Contains(body, "账号暂时不能登录") {
		t.Fatalf("threshold 2 did not lock: %s", body)
	}
	clearLock(t, admin2, ts2.URL, "alice")
	status, _ = login(t, bob, ts2.URL, "alice", "alice-password", "")
	if status != http.StatusSeeOther {
		t.Fatalf("admin clear lock: %d", status)
	}
}

func TestLogoutInvalidatesCookie(t *testing.T) {
	_, ts, _ := startServer(t, 3, time.Hour, 2*time.Hour)
	c := newClient(t)
	createAdmin(t, c, ts.URL, "admin", "admin-password")
	status, body, _ := get(t, c, ts.URL+"/")
	if status != http.StatusOK || !strings.Contains(body, "已登录：admin") {
		t.Fatalf("before logout %d %s", status, body)
	}
	saved := sessionValue(t, c, ts.URL)
	logout(t, c, ts.URL)
	status, _, res := get(t, c, ts.URL+"/")
	if status != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
		t.Fatalf("after logout %d %s", status, res.Header.Get("Location"))
	}
	replay(t, ts.URL, saved)
}

func TestLoginWithoutTOTP(t *testing.T) {
	_, ts, dbPath := startServer(t, 3, time.Hour, 2*time.Hour)
	admin := newClient(t)
	createAdmin(t, admin, ts.URL, "admin", "admin-password")
	createUser(t, admin, ts.URL, "alice", "alice-password")
	alice := newClient(t)
	status, body := login(t, alice, ts.URL, "alice", "alice-password", "")
	if status != http.StatusSeeOther {
		t.Fatalf("login without totp %d %s", status, body)
	}
	status, body, _ = get(t, alice, ts.URL+"/")
	if status != http.StatusOK || !strings.Contains(body, "已登录：alice") {
		t.Fatalf("home %d %s", status, body)
	}
	db := openDB(t, dbPath)
	var enabled int
	if err := db.QueryRow(`SELECT totp_enabled FROM users WHERE username = 'alice'`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatal("totp was enabled")
	}
}

func TestDisableDeletesLoginTokens(t *testing.T) {
	_, ts, dbPath := startServer(t, 3, time.Hour, 2*time.Hour)
	admin := newClient(t)
	createAdmin(t, admin, ts.URL, "admin", "admin-password")
	createUser(t, admin, ts.URL, "alice", "alice-password")
	if !strings.Contains(usersPage(t, admin, ts.URL), `data-username="alice" data-role="user"`) {
		t.Fatal("posted role was honored")
	}
	alice := newClient(t)
	status, _ := login(t, alice, ts.URL, "alice", "alice-password", "")
	if status != http.StatusSeeOther {
		t.Fatalf("user login %d", status)
	}
	saved := sessionValue(t, alice, ts.URL)
	id := userID(t, admin, ts.URL, "alice")
	db := openDB(t, dbPath)
	var tokens int
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_tokens WHERE user_id = ?`, id).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 1 {
		t.Fatalf("tokens before disable = %d", tokens)
	}
	disableUser(t, admin, ts.URL, id)
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_tokens WHERE user_id = ?`, id).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatalf("tokens after disable = %d", tokens)
	}
	replay(t, ts.URL, saved)
	status, body := login(t, alice, ts.URL, "alice", "alice-password", "")
	if status != http.StatusUnauthorized || !strings.Contains(body, "账号已停用") {
		t.Fatalf("disabled login %d %s", status, body)
	}
}

func TestTOTPOptionalAndAdminCanClear(t *testing.T) {
	_, ts, dbPath := startServer(t, 2, time.Hour, 2*time.Hour)
	admin := newClient(t)
	createAdmin(t, admin, ts.URL, "admin", "admin-password")
	createUser(t, admin, ts.URL, "alice", "alice-password")
	alice := newClient(t)
	if status, body := login(t, alice, ts.URL, "alice", "alice-password", ""); status != http.StatusSeeOther {
		t.Fatalf("pre-totp login %d %s", status, body)
	}
	_, page, _ := get(t, alice, ts.URL+"/account/totp")
	status, body, _ := postForm(t, alice, ts.URL+"/account/totp/start", url.Values{"csrf": {mustCSRF(t, page)}})
	if status != http.StatusOK {
		t.Fatalf("start totp %d %s", status, body)
	}
	secret := mustSecret(t, body)
	status, later, _ := get(t, alice, ts.URL+"/account/totp")
	if strings.Contains(later, secret) {
		t.Fatal("secret shown again")
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, body, res := postForm(t, alice, ts.URL+"/account/totp/confirm", url.Values{
		"csrf": {mustCSRF(t, body)},
		"code": {code},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("confirm %d %s", status, body)
	}
	_ = res
	_, enabledPage, _ := get(t, alice, ts.URL+"/account/totp")
	if strings.Contains(enabledPage, secret) || !strings.Contains(enabledPage, "已启用") {
		t.Fatalf("enabled page leaked or missing state: %s", enabledPage)
	}
	logout(t, alice, ts.URL)

	status, body = login(t, alice, ts.URL, "alice", "alice-password", "")
	if status != http.StatusUnauthorized || !strings.Contains(body, "账号或口令不正确") {
		t.Fatalf("missing code %d %s", status, body)
	}
	db := openDB(t, dbPath)
	var attempts int
	var locked sql.NullString
	if err := db.QueryRow(`SELECT failed_attempts, locked_until FROM users WHERE username = 'alice'`).Scan(&attempts, &locked); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || locked.Valid {
		t.Fatalf("after one missing code attempts=%d locked=%v", attempts, locked.Valid)
	}
	bad := wrongCode(code)
	status, body = login(t, alice, ts.URL, "alice", "alice-password", bad)
	if !strings.Contains(body, "账号暂时不能登录") {
		t.Fatalf("second totp failure did not lock: %d %s", status, body)
	}
	if err := db.QueryRow(`SELECT failed_attempts, locked_until FROM users WHERE username = 'alice'`).Scan(&attempts, &locked); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || !locked.Valid {
		t.Fatalf("after second totp failure attempts=%d locked=%v", attempts, locked.Valid)
	}
	good, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, body = login(t, alice, ts.URL, "alice", "alice-password", good)
	if !strings.Contains(body, "账号暂时不能登录") {
		t.Fatalf("locked totp login %d %s", status, body)
	}
	clearLock(t, admin, ts.URL, "alice")
	good, err = totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, body = login(t, alice, ts.URL, "alice", "alice-password", good)
	if status != http.StatusSeeOther {
		t.Fatalf("login after clear %d %s", status, body)
	}
	clearTOTP(t, admin, ts.URL, "alice")
	logout(t, alice, ts.URL)
	status, body = login(t, alice, ts.URL, "alice", "alice-password", "")
	if status != http.StatusSeeOther {
		t.Fatalf("login after totp cleared %d %s", status, body)
	}
	var enabled int
	var cipher []byte
	if err := db.QueryRow(`SELECT totp_enabled, totp_secret_ciphertext FROM users WHERE username = 'alice'`).Scan(&enabled, &cipher); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 || len(cipher) != 0 {
		t.Fatalf("totp not cleared enabled=%d cipher=%d", enabled, len(cipher))
	}
}

func startServer(t *testing.T, failures int, lockFor, ttl time.Duration) (*web.Server, *httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{
		Listen:          "127.0.0.1:0",
		Database:        dir + "/Stile.db",
		MasterKey:       dir + "/master.key",
		SessionTTL:      ttl,
		LockoutFailures: failures,
		LockoutDuration: lockFor,
	}
	key, err := config.LoadOrCreateMasterKey(cfg.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	srv, err := web.New(cfg, db, key)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts, cfg.Database
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func createAdmin(t *testing.T, c *http.Client, base, username, password string) {
	t.Helper()
	status, body, _ := get(t, c, base+"/setup")
	if status != http.StatusOK {
		t.Fatalf("setup %d %s", status, body)
	}
	status, body, res := postForm(t, c, base+"/setup", url.Values{
		"csrf":     {mustCSRF(t, body)},
		"username": {username},
		"password": {password},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("create admin %d %s", status, body)
	}
	if res.Header.Get("Location") != "/" {
		t.Fatalf("location %s", res.Header.Get("Location"))
	}
}

func createUser(t *testing.T, admin *http.Client, base, username, password string) {
	t.Helper()
	page := usersPage(t, admin, base)
	status, body, res := postForm(t, admin, base+"/admin/users", url.Values{
		"csrf":     {mustCSRF(t, page)},
		"username": {username},
		"password": {password},
		"role":     {"admin"},
	})
	if status != http.StatusSeeOther || res.Header.Get("Location") != "/admin/users?notice=created" {
		t.Fatalf("create user %d %s", status, body)
	}
}

func usersPage(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	status, body, _ := get(t, c, base+"/admin/users")
	if status != http.StatusOK {
		t.Fatalf("users %d %s", status, body)
	}
	return body
}

func userID(t *testing.T, admin *http.Client, base, username string) string {
	t.Helper()
	body := usersPage(t, admin, base)
	re := regexp.MustCompile(`data-username="` + regexp.QuoteMeta(username) + `" data-role="(?:admin|user)" data-id="([0-9a-f-]+)"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("user %s not on page: %s", username, body)
	}
	return m[1]
}

func disableUser(t *testing.T, admin *http.Client, base, id string) {
	t.Helper()
	page := usersPage(t, admin, base)
	status, body, res := postForm(t, admin, base+"/admin/users/"+id+"/disable", url.Values{
		"csrf": {mustCSRF(t, page)},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=disabled") {
		t.Fatalf("disable %d %s", status, body)
	}
}

func clearLock(t *testing.T, admin *http.Client, base, username string) {
	t.Helper()
	id := userID(t, admin, base, username)
	page := usersPage(t, admin, base)
	status, body, res := postForm(t, admin, base+"/admin/users/"+id+"/clear-lock", url.Values{
		"csrf": {mustCSRF(t, page)},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=lock-cleared") {
		t.Fatalf("clear lock %d %s location %s", status, body, res.Header.Get("Location"))
	}
}

func clearTOTP(t *testing.T, admin *http.Client, base, username string) {
	t.Helper()
	id := userID(t, admin, base, username)
	page := usersPage(t, admin, base)
	status, body, res := postForm(t, admin, base+"/admin/users/"+id+"/clear-totp", url.Values{
		"csrf": {mustCSRF(t, page)},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=totp-cleared") {
		t.Fatalf("clear totp %d %s", status, body)
	}
}

func login(t *testing.T, c *http.Client, base, username, password, code string) (int, string) {
	t.Helper()
	status, body, res := get(t, c, base+"/login")
	if status == http.StatusSeeOther {
		t.Fatalf("login page redirected to %s", res.Header.Get("Location"))
	}
	if status != http.StatusOK {
		t.Fatalf("login page %d %s", status, body)
	}
	status, body, _ = postForm(t, c, base+"/login", url.Values{
		"csrf":     {mustCSRF(t, body)},
		"username": {username},
		"password": {password},
		"code":     {code},
	})
	return status, body
}

func logout(t *testing.T, c *http.Client, base string) {
	t.Helper()
	status, body, _ := get(t, c, base+"/")
	if status != http.StatusOK {
		t.Fatalf("home before logout %d %s", status, body)
	}
	status, body, res := postForm(t, c, base+"/logout", url.Values{"csrf": {mustCSRF(t, body)}})
	if status != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
		t.Fatalf("logout %d %s", status, body)
	}
}

func sessionValue(t *testing.T, c *http.Client, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "stile_session" && ck.Value != "" {
			return ck.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func replay(t *testing.T, base, value string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "stile_session", Value: value})
	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
		t.Fatalf("replayed cookie %d %s %s", res.StatusCode, res.Header.Get("Location"), body)
	}
}

func get(t *testing.T, c *http.Client, rawURL string) (int, string, *http.Response) {
	t.Helper()
	res, err := c.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, readBody(t, res), res
}

func postForm(t *testing.T, c *http.Client, rawURL string, v url.Values) (int, string, *http.Response) {
	t.Helper()
	res, err := c.PostForm(rawURL, v)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, readBody(t, res), res
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)
var secretRe = regexp.MustCompile(`id="totp-secret">([A-Z2-7]+)</code>`)

func mustCSRF(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("csrf not found in %s", body)
	}
	return m[1]
}

func mustSecret(t *testing.T, body string) string {
	t.Helper()
	m := secretRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("secret not found in %s", body)
	}
	return m[1]
}

func wrongCode(code string) string {
	if strings.HasPrefix(code, "0") {
		return "1" + code[1:]
	}
	return "0" + code[1:]
}

func openDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func tableNames(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return names
}

func tableColumns(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}
