package web_test

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestGrantsVisibilityAndOpen(t *testing.T) {
	_, ts, dbPath := startServer(t, 3, time.Hour, 2*time.Hour)
	admin := newClient(t)
	createAdmin(t, admin, ts.URL, "admin", "admin-password")
	createUser(t, admin, ts.URL, "alice", "alice-password")
	createUser(t, admin, ts.URL, "bob", "bob-password")
	alice := newClient(t)
	if status, body := login(t, alice, ts.URL, "alice", "alice-password", ""); status != http.StatusSeeOther {
		t.Fatalf("alice login %d %s", status, body)
	}
	bob := newClient(t)
	if status, body := login(t, bob, ts.URL, "bob", "bob-password", ""); status != http.StatusSeeOther {
		t.Fatalf("bob login %d %s", status, body)
	}
	aliceID := userID(t, admin, ts.URL, "alice")
	bobID := userID(t, admin, ts.URL, "bob")

	const secret = "grant-secret-zz-not-on-user-page"
	credPage := credentialsPage(t, admin, ts.URL)
	status, body, res := postForm(t, admin, ts.URL+"/admin/credentials", url.Values{
		"csrf":       {mustCSRF(t, credPage)},
		"name":       {"bound-cred"},
		"kind":       {"password"},
		"login_name": {"root"},
		"secret":     {secret},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("credential %d %s", status, body)
	}
	credID := credentialID(t, credentialsPage(t, admin, ts.URL), "bound-cred", "password", "root", "")

	direct := makeAsset(t, admin, ts.URL, "direct-host", "192.0.2.10", credID)
	grouped := makeAsset(t, admin, ts.URL, "group-host", "192.0.2.20", "")
	both := makeAsset(t, admin, ts.URL, "both-host", "192.0.2.30", "")
	hidden := makeAsset(t, admin, ts.URL, "hidden-host", "192.0.2.40", "")
	bobAsset := makeAsset(t, admin, ts.URL, "bob-host", "192.0.2.50", "")

	groupPage := groupsPage(t, admin, ts.URL)
	status, body, res = postForm(t, admin, ts.URL+"/admin/groups", url.Values{
		"csrf": {mustCSRF(t, groupPage)},
		"name": {"ops"},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=group-created") {
		t.Fatalf("create group %d %s", status, body)
	}
	opsID := groupID(t, groupsPage(t, admin, ts.URL), "ops")
	addMember(t, admin, ts.URL, opsID, aliceID)
	addMember(t, admin, ts.URL, opsID, bobID)

	grantTo(t, admin, ts.URL, direct, "user", aliceID)
	grantTo(t, admin, ts.URL, grouped, "group", opsID)
	grantTo(t, admin, ts.URL, both, "user", aliceID)
	grantTo(t, admin, ts.URL, both, "group", opsID)
	grantTo(t, admin, ts.URL, bobAsset, "user", bobID)

	grants := grantsPage(t, admin, ts.URL)
	status, body, _ = postForm(t, admin, ts.URL+"/admin/grants", url.Values{
		"csrf":         {mustCSRF(t, grants)},
		"asset_id":     {direct},
		"subject_type": {"user"},
		"user_id":      {aliceID},
		"group_id":     {opsID},
	})
	if status != http.StatusConflict || !strings.Contains(body, "同一资产和主体已经有授权") {
		t.Fatalf("duplicate grant %d %s", status, body)
	}
	db := openDB(t, dbPath)
	var pair int
	if err := db.QueryRow(`SELECT COUNT(*) FROM grants WHERE asset_id = ? AND subject_type = 'user' AND subject_id = ?`, direct, aliceID).Scan(&pair); err != nil || pair != 1 {
		t.Fatalf("duplicate rows %d %v", pair, err)
	}

	alicePage := visiblePage(t, alice, ts.URL)
	aliceNames := visibleNames(t, alicePage)
	if aliceNames != "both-host,direct-host,group-host" {
		t.Fatalf("alice list %s\n%s", aliceNames, alicePage)
	}
	if strings.Count(alicePage, `data-name="both-host"`) != 1 {
		t.Fatal("both-host is not a single union row")
	}
	for _, banned := range []string{secret, credID, "credential", "hidden-host", "bob-host", "192.0.2.40", "192.0.2.50"} {
		if strings.Contains(alicePage, banned) {
			t.Fatalf("alice list contains %q", banned)
		}
	}
	if !regexp.MustCompile(`data-asset-id="` + direct + `" data-name="direct-host" data-protocol="ssh" data-host="192.0.2.10" data-port="22"`).MatchString(alicePage) {
		t.Fatalf("alice asset object: %s", alicePage)
	}

	adminPage := visiblePage(t, admin, ts.URL)
	if visibleNames(t, adminPage) != "bob-host,both-host,direct-host,group-host,hidden-host" {
		t.Fatalf("admin list %s", visibleNames(t, adminPage))
	}
	if !strings.Contains(adminPage, `data-asset-id="`+direct+`" data-name="direct-host" data-protocol="ssh" data-host="192.0.2.10" data-port="22" data-credential-id="`+credID+`"`) {
		t.Fatalf("admin asset missing credential id: %s", adminPage)
	}
	if strings.Contains(adminPage, secret) {
		t.Fatal("admin asset list contains the secret")
	}
	managed := assetsPage(t, admin, ts.URL)
	for _, name := range []string{"direct-host", "group-host", "both-host", "hidden-host", "bob-host"} {
		if !strings.Contains(managed, `data-name="`+name+`"`) {
			t.Fatalf("admin management list missing %s", name)
		}
	}

	bobPage := visiblePage(t, bob, ts.URL)
	if visibleNames(t, bobPage) != "bob-host,both-host,group-host" {
		t.Fatalf("bob list %s", visibleNames(t, bobPage))
	}

	status, body, res = get(t, alice, ts.URL+"/assets/"+hidden+"/open")
	if status != http.StatusForbidden || !strings.Contains(body, "没有授权，打不开") || strings.Contains(body, "192.0.2.40") || strings.Contains(body, secret) {
		t.Fatalf("alice hidden open %d %s", status, body)
	}
	status, body, _ = get(t, alice, ts.URL+"/assets/"+direct+"/open")
	if status != http.StatusConflict || !strings.Contains(body, "还没有登记主机密钥指纹") || !strings.Contains(body, "不连接") || !strings.Contains(body, "direct-host") {
		t.Fatalf("alice direct open %d %s", status, body)
	}
	if strings.Contains(body, "WebSocket") || strings.Contains(body, credID) || strings.Contains(body, secret) || strings.Contains(body, "credential") {
		t.Fatal("open page connects or exposes the credential")
	}
	status, body, _ = get(t, alice, ts.URL+"/assets/"+grouped+"/open")
	if status != http.StatusConflict || !strings.Contains(body, "group-host") || !strings.Contains(body, "未绑定凭据") {
		t.Fatalf("alice group open %d %s", status, body)
	}
	status, body, _ = get(t, admin, ts.URL+"/assets/"+hidden+"/open")
	if status != http.StatusForbidden || !strings.Contains(body, "没有授权，打不开") || strings.Contains(body, "192.0.2.40") {
		t.Fatalf("admin hidden open %d %s", status, body)
	}
	status, body, _ = get(t, admin, ts.URL+"/assets/"+direct+"/open")
	if status != http.StatusForbidden || !strings.Contains(body, "没有授权，打不开") {
		t.Fatalf("admin ungranted open %d %s", status, body)
	}
	anon := newClient(t)
	status, _, res = get(t, anon, ts.URL+"/assets/"+direct+"/open")
	if status != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
		t.Fatalf("anonymous open %d %s", status, res.Header.Get("Location"))
	}
	status, body, _ = get(t, alice, ts.URL+"/admin/grants")
	if status != http.StatusForbidden {
		t.Fatalf("alice grants %d %s", status, body)
	}

	directGrant := grantRowID(t, grantsPage(t, admin, ts.URL), direct, "user", aliceID)
	revoke := grantsPage(t, admin, ts.URL)
	status, body, res = postForm(t, admin, ts.URL+"/admin/grants/"+directGrant+"/delete", url.Values{"csrf": {mustCSRF(t, revoke)}})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=grant-revoked") {
		t.Fatalf("revoke %d %s", status, body)
	}
	if visibleNames(t, visiblePage(t, alice, ts.URL)) != "both-host,group-host" {
		t.Fatalf("alice after revoke %s", visibleNames(t, visiblePage(t, alice, ts.URL)))
	}
	status, body, _ = get(t, alice, ts.URL+"/assets/"+direct+"/open")
	if status != http.StatusForbidden || !strings.Contains(body, "没有授权，打不开") {
		t.Fatalf("alice revoked open %d %s", status, body)
	}

	removeMember(t, admin, ts.URL, opsID, aliceID)
	if visibleNames(t, visiblePage(t, alice, ts.URL)) != "both-host" {
		t.Fatalf("alice after leaving group %s", visibleNames(t, visiblePage(t, alice, ts.URL)))
	}
	if visibleNames(t, visiblePage(t, bob, ts.URL)) != "bob-host,both-host,group-host" {
		t.Fatalf("bob unchanged %s", visibleNames(t, visiblePage(t, bob, ts.URL)))
	}

	groups := groupsPage(t, admin, ts.URL)
	status, body, res = postForm(t, admin, ts.URL+"/admin/groups/"+opsID+"/delete", url.Values{"csrf": {mustCSRF(t, groups)}})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=group-deleted") {
		t.Fatalf("delete group %d %s", status, body)
	}
	var groupGrants, members int
	if err := db.QueryRow(`SELECT COUNT(*) FROM grants WHERE subject_type = 'group' AND subject_id = ?`, opsID).Scan(&groupGrants); err != nil || groupGrants != 0 {
		t.Fatalf("group grants left %d %v", groupGrants, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM group_members WHERE group_id = ?`, opsID).Scan(&members); err != nil || members != 0 {
		t.Fatalf("members left %d %v", members, err)
	}
	if visibleNames(t, visiblePage(t, alice, ts.URL)) != "both-host" {
		t.Fatalf("alice keeps direct both %s", visibleNames(t, visiblePage(t, alice, ts.URL)))
	}
	if visibleNames(t, visiblePage(t, bob, ts.URL)) != "bob-host" {
		t.Fatalf("bob after group delete %s", visibleNames(t, visiblePage(t, bob, ts.URL)))
	}
	if !strings.Contains(visiblePage(t, admin, ts.URL), "group-host") {
		t.Fatal("deleted group grant also deleted the asset")
	}

	assetPage := assetsPage(t, admin, ts.URL)
	status, body, res = postForm(t, admin, ts.URL+"/admin/assets/"+bobAsset+"/delete", url.Values{"csrf": {mustCSRF(t, assetPage)}})
	if status != http.StatusSeeOther {
		t.Fatalf("delete asset %d %s", status, body)
	}
	var assetGrants int
	if err := db.QueryRow(`SELECT COUNT(*) FROM grants WHERE asset_id = ?`, bobAsset).Scan(&assetGrants); err != nil || assetGrants != 0 {
		t.Fatalf("asset grants left %d %v", assetGrants, err)
	}

	createUser(t, admin, ts.URL, "carol", "carol-password")
	carolID := userID(t, admin, ts.URL, "carol")
	groups = groupsPage(t, admin, ts.URL)
	status, body, _ = postForm(t, admin, ts.URL+"/admin/groups", url.Values{
		"csrf": {mustCSRF(t, groups)},
		"name": {"extra"},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("extra group %d %s", status, body)
	}
	extraID := groupID(t, groupsPage(t, admin, ts.URL), "extra")
	addMember(t, admin, ts.URL, extraID, carolID)
	grantTo(t, admin, ts.URL, hidden, "user", carolID)
	users := usersPage(t, admin, ts.URL)
	status, body, res = postForm(t, admin, ts.URL+"/admin/users/"+carolID+"/delete", url.Values{"csrf": {mustCSRF(t, users)}})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=user-deleted") {
		t.Fatalf("delete user %d %s", status, body)
	}
	var userGrants, carolMembers, carolRows, extraRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM grants WHERE subject_id = ?`, carolID).Scan(&userGrants); err != nil || userGrants != 0 {
		t.Fatalf("user grants left %d %v", userGrants, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM group_members WHERE user_id = ?`, carolID).Scan(&carolMembers); err != nil || carolMembers != 0 {
		t.Fatalf("memberships left %d %v", carolMembers, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE id = ?`, carolID).Scan(&carolRows); err != nil || carolRows != 0 {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_groups WHERE id = ?`, extraID).Scan(&extraRows); err != nil || extraRows != 1 {
		t.Fatalf("group removed with the user %d %v", extraRows, err)
	}

	cols := tableColumns(t, db, "grants")
	for _, banned := range []string{"permission", "upload", "download", "edit", "rename", "clipboard"} {
		if cols[banned] {
			t.Fatalf("grants has %s", banned)
		}
	}
	for _, want := range []string{"asset_id", "subject_type", "subject_id", "created_by"} {
		if !cols[want] {
			t.Fatalf("grants missing %s", want)
		}
	}
}

func makeAsset(t *testing.T, c *http.Client, base, name, host, credentialID string) string {
	t.Helper()
	page := assetsPage(t, c, base)
	status, body, res := postForm(t, c, base+"/admin/assets", url.Values{
		"csrf":          {mustCSRF(t, page)},
		"name":          {name},
		"protocol":      {"ssh"},
		"host":          {host},
		"credential_id": {credentialID},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=asset-saved") {
		t.Fatalf("create asset %s %d %s", name, status, body)
	}
	id, _, cred, _ := assetRow(t, assetsPage(t, c, base), name, "ssh", host)
	if cred != credentialID {
		t.Fatalf("asset %s credential %q want %q", name, cred, credentialID)
	}
	return id
}

func groupsPage(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	status, body, _ := get(t, c, base+"/admin/groups")
	if status != http.StatusOK {
		t.Fatalf("groups %d %s", status, body)
	}
	return body
}

func grantsPage(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	status, body, _ := get(t, c, base+"/admin/grants")
	if status != http.StatusOK {
		t.Fatalf("grants %d %s", status, body)
	}
	return body
}

func visiblePage(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	status, body, _ := get(t, c, base+"/assets")
	if status != http.StatusOK {
		t.Fatalf("assets %d %s", status, body)
	}
	return body
}

func groupID(t *testing.T, body, name string) string {
	t.Helper()
	re := regexp.MustCompile(`data-group-id="([0-9a-f-]+)" data-name="` + regexp.QuoteMeta(name) + `"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("group %s not on page: %s", name, body)
	}
	return m[1]
}

func addMember(t *testing.T, c *http.Client, base, groupID, userID string) {
	t.Helper()
	status, body, _ := get(t, c, base+"/admin/groups/"+groupID)
	if status != http.StatusOK {
		t.Fatalf("group page %d %s", status, body)
	}
	status, body, res := postForm(t, c, base+"/admin/groups/"+groupID+"/members", url.Values{
		"csrf":    {mustCSRF(t, body)},
		"user_id": {userID},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=member-added") {
		t.Fatalf("add member %d %s", status, body)
	}
}

func removeMember(t *testing.T, c *http.Client, base, groupID, userID string) {
	t.Helper()
	status, body, _ := get(t, c, base+"/admin/groups/"+groupID)
	if status != http.StatusOK {
		t.Fatalf("group page %d %s", status, body)
	}
	status, body, res := postForm(t, c, base+"/admin/groups/"+groupID+"/members/"+userID+"/delete", url.Values{
		"csrf": {mustCSRF(t, body)},
	})
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=member-removed") {
		t.Fatalf("remove member %d %s", status, body)
	}
}

func grantTo(t *testing.T, c *http.Client, base, assetID, subjectType, subjectID string) {
	t.Helper()
	page := grantsPage(t, c, base)
	values := url.Values{
		"csrf":         {mustCSRF(t, page)},
		"asset_id":     {assetID},
		"subject_type": {subjectType},
	}
	if subjectType == "user" {
		values.Set("user_id", subjectID)
	} else {
		values.Set("group_id", subjectID)
	}
	status, body, res := postForm(t, c, base+"/admin/grants", values)
	if status != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "notice=grant-created") {
		t.Fatalf("grant %s %s %d %s", assetID, subjectType, status, body)
	}
}

func grantRowID(t *testing.T, body, assetID, subjectType, subjectID string) string {
	t.Helper()
	re := regexp.MustCompile(`data-grant-id="([0-9a-f-]+)" data-asset-id="` + assetID + `" data-asset-name="[^"]*" data-subject-type="` + subjectType + `" data-subject-id="` + subjectID + `"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("grant %s %s not on page: %s", assetID, subjectType, body)
	}
	return m[1]
}

func visibleNames(t *testing.T, body string) string {
	t.Helper()
	re := regexp.MustCompile(`class="visible-asset"[^>]*data-name="([^"]+)"`)
	found := re.FindAllStringSubmatch(body, -1)
	names := make([]string, 0, len(found))
	for _, m := range found {
		names = append(names, m[1])
	}
	return strings.Join(names, ",")
}
