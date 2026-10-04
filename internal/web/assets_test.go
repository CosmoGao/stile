package web_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"html"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestAssetsAndCredentials(t *testing.T) {
	_, ts, dbPath := startServer(t, 3, time.Hour, 2*time.Hour)
	admin := newClient(t)
	createAdmin(t, admin, ts.URL, "admin", "admin-password")
	createUser(t, admin, ts.URL, "alice", "alice-password")
	alice := newClient(t)
	if status, body := login(t, alice, ts.URL, "alice", "alice-password", ""); status != http.StatusSeeOther {
		t.Fatalf("alice login %d %s", status, body)
	}

	const (
		password    = "pw-plain-9f3c1a-4b7e"
		replaced    = "pw-replaced-77aa-1c0d"
		ignoredPass = "passphrase-should-not-stick"
		keyPass     = "key-passphrase-not-in-db-44"
	)
	pemText, wantFP := generateKey(t, keyPass)
	submittedLine := pemBodyLine(pemText)

	credPage := credentialsPage(t, admin, ts.URL)
	status, body, res := postForm(t, admin, ts.URL+"/admin/credentials", url.Values{
		"csrf":           {mustCSRF(t, credPage)},
		"name":           {"shared-login"},
		"kind":           {"password"},
		"login_name":     {"root"},
		"secret":         {password},
		"key_passphrase": {ignoredPass},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=credential-saved") {
		t.Fatalf("create credential %d %s %s", status, res.Header.Get("Location"), body)
	}
	if strings.Contains(body, password) || strings.Contains(res.Header.Get("Location"), password) || strings.Contains(body, ignoredPass) {
		t.Fatal("create response contains the password or key passphrase")
	}
	list := credentialsPage(t, admin, ts.URL)
	if strings.Contains(list, password) || strings.Contains(list, ignoredPass) || strings.Contains(list, "credential-secret") {
		t.Fatal("credential list contains a secret")
	}
	credID := credentialID(t, list, "shared-login", "password", "root", "")
	if strings.Contains(list, `data-fingerprint="SHA256:`) && strings.Contains(list, `data-name="shared-login"`) {
		t.Fatal("password credential shows a fingerprint")
	}

	db := openDB(t, dbPath)
	var nonce, ct []byte
	if err := db.QueryRow(`SELECT secret_nonce, secret_ciphertext FROM credentials WHERE id = ?`, credID).Scan(&nonce, &ct); err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 12 || bytes.Contains(ct, []byte(password)) || bytes.Contains(nonce, []byte(password)) {
		t.Fatal("stored credential is not ciphertext")
	}
	rawDB := readDBFiles(t, dbPath)
	for _, banned := range []string{password, ignoredPass} {
		if bytes.Contains(rawDB, []byte(banned)) {
			t.Fatalf("database file contains %q", banned)
		}
	}

	var updatedBefore string
	var tokensBefore int
	if err := db.QueryRow(`SELECT updated_at FROM credentials WHERE id = ?`, credID).Scan(&updatedBefore); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_tokens`).Scan(&tokensBefore); err != nil {
		t.Fatal(err)
	}
	status, viewBody, _ := get(t, admin, ts.URL+"/admin/credentials/"+credID)
	if status != http.StatusOK || !strings.Contains(viewBody, `<pre id="credential-secret">`+password+`</pre>`) {
		t.Fatalf("admin view missing plaintext: %d %s", status, viewBody)
	}
	var updatedAfter string
	var tokensAfter int
	if err := db.QueryRow(`SELECT updated_at FROM credentials WHERE id = ?`, credID).Scan(&updatedAfter); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_tokens`).Scan(&tokensAfter); err != nil {
		t.Fatal(err)
	}
	if updatedBefore != updatedAfter || tokensBefore != tokensAfter {
		t.Fatalf("view wrote state updated %s -> %s tokens %d -> %d", updatedBefore, updatedAfter, tokensBefore, tokensAfter)
	}

	anon := newClient(t)
	status, anonBody, anonRes := get(t, anon, ts.URL+"/admin/credentials/"+credID)
	if status != http.StatusSeeOther || anonRes.Header.Get("Location") != "/login" || strings.Contains(anonBody, password) {
		t.Fatalf("anonymous view %d %s %s", status, anonRes.Header.Get("Location"), anonBody)
	}

	list = credentialsPage(t, admin, ts.URL)
	status, body, res = postForm(t, admin, ts.URL+"/admin/credentials/"+credID, url.Values{
		"csrf":       {mustCSRF(t, list)},
		"name":       {"shared-login"},
		"login_name": {"root"},
		"secret":     {replaced},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=credential-replaced") {
		t.Fatalf("replace %d %s %s", status, res.Header.Get("Location"), body)
	}
	if strings.Contains(body, password) || strings.Contains(body, replaced) || strings.Contains(res.Header.Get("Location"), replaced) {
		t.Fatal("replace response contains a password")
	}
	list = credentialsPage(t, admin, ts.URL)
	if strings.Contains(list, password) || strings.Contains(list, replaced) {
		t.Fatal("list after replace contains a password")
	}
	status, viewBody, _ = get(t, admin, ts.URL+"/admin/credentials/"+credID)
	if status != http.StatusOK || !strings.Contains(viewBody, replaced) || strings.Contains(viewBody, password) {
		t.Fatalf("view after replace %d %s", status, viewBody)
	}
	rawDB = readDBFiles(t, dbPath)
	if bytes.Contains(rawDB, []byte(replaced)) || bytes.Contains(rawDB, []byte(password)) {
		t.Fatal("database file contains a password after replace")
	}

	list = credentialsPage(t, admin, ts.URL)
	status, body, res = postForm(t, admin, ts.URL+"/admin/credentials", url.Values{
		"csrf":           {mustCSRF(t, list)},
		"name":           {"linux-key"},
		"kind":           {"ssh_private_key"},
		"login_name":     {"root"},
		"secret":         {pemText},
		"key_passphrase": {keyPass},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("create key %d %s", status, body)
	}
	if strings.Contains(body, keyPass) || strings.Contains(body, submittedLine) || strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("create key response contains key material")
	}
	list = credentialsPage(t, admin, ts.URL)
	if strings.Contains(list, keyPass) || strings.Contains(list, submittedLine) || strings.Contains(list, "PRIVATE KEY") {
		t.Fatal("credential list contains the private key")
	}
	if !strings.Contains(list, wantFP) {
		t.Fatalf("list missing fingerprint %s", wantFP)
	}
	keyID := credentialID(t, list, "linux-key", "ssh_private_key", "root", wantFP)
	status, viewBody, _ = get(t, admin, ts.URL+"/admin/credentials/"+keyID)
	if status != http.StatusOK {
		t.Fatalf("view key %d %s", status, viewBody)
	}
	revealed := revealedSecret(t, viewBody)
	if strings.Contains(revealed, keyPass) || strings.Contains(revealed, submittedLine) {
		t.Fatal("view returned the passphrase or the still-encrypted body")
	}
	rawKey, err := ssh.ParseRawPrivateKey([]byte(revealed))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(signer.PublicKey()) != wantFP {
		t.Fatal("viewed key fingerprint mismatch")
	}
	rawDB = readDBFiles(t, dbPath)
	for _, banned := range []string{keyPass, "PRIVATE KEY", submittedLine, pemBodyLine(revealed)} {
		if banned != "" && bytes.Contains(rawDB, []byte(banned)) {
			t.Fatalf("database file contains %q", banned)
		}
	}
	list = credentialsPage(t, admin, ts.URL)
	if strings.Contains(list, pemBodyLine(revealed)) || strings.Contains(list, "PRIVATE KEY") {
		t.Fatal("list contains the unwrapped key")
	}

	for _, target := range []string{
		"/admin/credentials",
		"/admin/credentials/" + credID,
		"/admin/credentials/" + keyID,
		"/admin/assets",
	} {
		status, body, _ = get(t, alice, ts.URL+target)
		if status != http.StatusForbidden {
			t.Fatalf("alice GET %s %d %s", target, status, body)
		}
		assertNoSecrets(t, body, password, replaced, keyPass, submittedLine, revealed)
	}
	status, body, _ = postForm(t, alice, ts.URL+"/admin/credentials", url.Values{
		"name": {"x"}, "kind": {"password"}, "login_name": {"root"}, "secret": {password},
	})
	if status != http.StatusForbidden {
		t.Fatalf("alice create %d %s", status, body)
	}
	assertNoSecrets(t, body, password, replaced, keyPass, submittedLine, revealed)
	status, body, _ = postForm(t, alice, ts.URL+"/admin/credentials/"+credID, url.Values{"secret": {password}})
	if status != http.StatusForbidden {
		t.Fatalf("alice replace %d %s", status, body)
	}
	status, home, _ := get(t, alice, ts.URL+"/")
	if status != http.StatusOK || strings.Contains(home, "/admin/assets") || strings.Contains(home, "/admin/credentials") || strings.Contains(home, "192.0.2.1") {
		t.Fatalf("alice home %d %s", status, home)
	}
	assertNoSecrets(t, home, password, replaced, keyPass, submittedLine, revealed)

	assetPage := assetsPage(t, admin, ts.URL)
	if strings.Contains(assetPage, replaced) || strings.Contains(assetPage, "PRIVATE KEY") {
		t.Fatal("asset page contains a secret before create")
	}
	status, body, res = postForm(t, admin, ts.URL+"/admin/assets", url.Values{
		"csrf":                     {mustCSRF(t, assetPage)},
		"name":                     {"linux-a"},
		"protocol":                 {"ssh"},
		"host":                     {"192.0.2.1"},
		"port":                     {""},
		"credential_id":            {credID},
		"ssh_host_key_fingerprint": {"SHA256:pinned-fingerprint"},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("create ssh a %d %s", status, body)
	}
	assetPage = assetsPage(t, admin, ts.URL)
	status, body, _ = postForm(t, admin, ts.URL+"/admin/assets", url.Values{
		"csrf":          {mustCSRF(t, assetPage)},
		"name":          {"linux-b"},
		"protocol":      {"ssh"},
		"host":          {"192.0.2.2"},
		"credential_id": {credID},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("create ssh b %d %s", status, body)
	}
	assetPage = assetsPage(t, admin, ts.URL)
	status, body, _ = postForm(t, admin, ts.URL+"/admin/assets", url.Values{
		"csrf":                     {mustCSRF(t, assetPage)},
		"name":                     {"win-1"},
		"protocol":                 {"rdp"},
		"host":                     {"192.0.2.10"},
		"ssh_host_key_fingerprint": {"SHA256:should-ignore"},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("create rdp %d %s", status, body)
	}
	assetPage = assetsPage(t, admin, ts.URL)
	if strings.Contains(assetPage, replaced) || strings.Contains(assetPage, revealed) || strings.Contains(assetPage, "PRIVATE KEY") {
		t.Fatal("asset page contains a secret")
	}
	aID, aPort, aCred, aKey := assetRow(t, assetPage, "linux-a", "ssh", "192.0.2.1")
	bID, bPort, bCred, _ := assetRow(t, assetPage, "linux-b", "ssh", "192.0.2.2")
	_, rPort, rCred, rKey := assetRow(t, assetPage, "win-1", "rdp", "192.0.2.10")
	if aPort != "22" || bPort != "22" || rPort != "3389" {
		t.Fatalf("ports a=%s b=%s rdp=%s", aPort, bPort, rPort)
	}
	if aCred != credID || bCred != credID {
		t.Fatalf("shared credential a=%s b=%s want %s", aCred, bCred, credID)
	}
	if aKey != "SHA256:pinned-fingerprint" || rKey != "" || rCred != "" {
		t.Fatalf("host key a=%q rdp key=%q rdp cred=%q", aKey, rKey, rCred)
	}
	var dbPort int
	var storedFP []byte
	if err := db.QueryRow(`SELECT port, ssh_host_key_fingerprint FROM assets WHERE name = 'win-1'`).Scan(&dbPort, &storedFP); err != nil {
		t.Fatal(err)
	}
	if dbPort != 3389 || len(storedFP) != 0 {
		t.Fatalf("rdp row port %d fingerprint %q", dbPort, storedFP)
	}
	if err := db.QueryRow(`SELECT port FROM assets WHERE name = 'linux-a'`).Scan(&dbPort); err != nil || dbPort != 22 {
		t.Fatalf("ssh port %d %v", dbPort, err)
	}

	credCols := tableColumns(t, db, "credentials")
	for _, name := range []string{"password", "passphrase", "plaintext", "private_key"} {
		if credCols[name] {
			t.Fatalf("credentials has %s", name)
		}
	}
	for _, name := range []string{"secret_nonce", "secret_ciphertext", "fingerprint", "login_name", "kind"} {
		if !credCols[name] {
			t.Fatalf("credentials missing %s", name)
		}
	}
	assetCols := tableColumns(t, db, "assets")
	for _, name := range []string{"password", "secret", "secret_ciphertext", "secret_nonce", "private_key", "passphrase", "nonce", "plaintext", "login_name"} {
		if assetCols[name] {
			t.Fatalf("assets has %s", name)
		}
	}
	for _, name := range []string{"credential_id", "ssh_host_key_fingerprint", "protocol", "host", "port"} {
		if !assetCols[name] {
			t.Fatalf("assets missing %s", name)
		}
	}

	list = credentialsPage(t, admin, ts.URL)
	status, body, _ = postForm(t, admin, ts.URL+"/admin/credentials/"+credID+"/delete", url.Values{"csrf": {mustCSRF(t, list)}})
	if status != http.StatusConflict || !strings.Contains(body, "仍被资产引用，不能删除") || strings.Contains(body, replaced) {
		t.Fatalf("delete referenced %d %s", status, body)
	}
	var still int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE id = ?`, credID).Scan(&still); err != nil || still != 1 {
		t.Fatalf("row after rejected delete %d %v", still, err)
	}

	unbind(t, admin, ts.URL, aID, "linux-a", "ssh", "192.0.2.1", "22", "SHA256:pinned-fingerprint")
	list = credentialsPage(t, admin, ts.URL)
	status, body, _ = postForm(t, admin, ts.URL+"/admin/credentials/"+credID+"/delete", url.Values{"csrf": {mustCSRF(t, list)}})
	if status != http.StatusConflict || !strings.Contains(body, "仍被资产引用，不能删除") {
		t.Fatalf("delete with one reference %d %s", status, body)
	}
	unbind(t, admin, ts.URL, bID, "linux-b", "ssh", "192.0.2.2", "22", "")
	list = credentialsPage(t, admin, ts.URL)
	status, body, res = postForm(t, admin, ts.URL+"/admin/credentials/"+credID+"/delete", url.Values{"csrf": {mustCSRF(t, list)}})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=credential-deleted") {
		t.Fatalf("delete unreferenced %d %s", status, body)
	}
	if strings.Contains(body, replaced) {
		t.Fatal("delete response contains the password")
	}
	list = credentialsPage(t, admin, ts.URL)
	if strings.Contains(list, `data-name="shared-login"`) || strings.Contains(list, replaced) {
		t.Fatal("deleted credential still listed")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE id = ?`, credID).Scan(&still); err != nil || still != 0 {
		t.Fatalf("credential remains %d %v", still, err)
	}

	names := tableNames(t, db)
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	allowed := map[string]bool{"users": true, "login_tokens": true, "schema_migrations": true, "credentials": true, "assets": true, "user_groups": true, "group_members": true, "grants": true, "web_sessions": true}
	if len(got) != len(allowed) {
		t.Fatalf("tables %v", names)
	}
	for n := range got {
		if !allowed[n] {
			t.Fatalf("unexpected table %s", n)
		}
	}
}

func credentialsPage(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	status, body, _ := get(t, c, base+"/admin/credentials")
	if status != http.StatusOK {
		t.Fatalf("credentials %d %s", status, body)
	}
	return html.UnescapeString(body)
}

func assetsPage(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	status, body, _ := get(t, c, base+"/admin/assets")
	if status != http.StatusOK {
		t.Fatalf("assets %d %s", status, body)
	}
	return html.UnescapeString(body)
}

func credentialID(t *testing.T, body, name, kind, login, fingerprint string) string {
	t.Helper()
	re := regexp.MustCompile(`data-credential-id="([0-9a-f-]+)" data-name="` + regexp.QuoteMeta(name) + `" data-kind="` + regexp.QuoteMeta(kind) + `" data-login-name="` + regexp.QuoteMeta(login) + `" data-fingerprint="` + regexp.QuoteMeta(fingerprint) + `"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("credential %s not on page: %s", name, body)
	}
	return m[1]
}

func assetRow(t *testing.T, body, name, protocol, host string) (id, port, credentialID, hostKey string) {
	t.Helper()
	re := regexp.MustCompile(`data-asset-id="([0-9a-f-]+)" data-name="` + regexp.QuoteMeta(name) + `" data-protocol="` + protocol + `" data-host="` + regexp.QuoteMeta(host) + `" data-port="([0-9]+)" data-credential-id="([^"]*)" data-host-key="([^"]*)"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("asset %s not on page: %s", name, body)
	}
	return m[1], m[2], m[3], m[4]
}

func unbind(t *testing.T, c *http.Client, base, id, name, protocol, host, port, fingerprint string) {
	t.Helper()
	page := assetsPage(t, c, base)
	status, body, res := postForm(t, c, base+"/admin/assets/"+id, url.Values{
		"csrf":                     {mustCSRF(t, page)},
		"name":                     {name},
		"protocol":                 {protocol},
		"host":                     {host},
		"port":                     {port},
		"credential_id":            {""},
		"ssh_host_key_fingerprint": {fingerprint},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=asset-saved") {
		t.Fatalf("unbind %s %d %s", name, status, body)
	}
}

func revealedSecret(t *testing.T, body string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)<pre id="credential-secret">(.*?)</pre>`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("secret element missing: %s", body)
	}
	return html.UnescapeString(m[1])
}

func assertNoSecrets(t *testing.T, body string, parts ...string) {
	t.Helper()
	body = html.UnescapeString(body)
	for _, part := range parts {
		if part != "" && strings.Contains(body, part) {
			t.Fatalf("response contains %q", part)
		}
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("response contains a private key")
	}
}

func generateKey(t *testing.T, passphrase string) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), ssh.FingerprintSHA256(signer.PublicKey())
}

func pemBodyLine(pemText string) string {
	for _, line := range strings.Split(pemText, "\n") {
		if len(line) > 40 && !strings.HasPrefix(line, "-----") {
			return line
		}
	}
	return ""
}

func readDBFiles(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if w, err := os.ReadFile(path + "-wal"); err == nil {
		b = append(b, w...)
	}
	return b
}
