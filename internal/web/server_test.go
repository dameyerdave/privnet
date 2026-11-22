package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dameyerdave/privnet/internal/cookbook"
	"github.com/dameyerdave/privnet/internal/store"
	"github.com/dameyerdave/privnet/internal/wg"
	webassets "github.com/dameyerdave/privnet/web"
)

type testApp struct {
	t   *testing.T
	ts  *httptest.Server
	srv *Server
}

func newTestApp(t *testing.T, baseURL string, opts ...func(*Config)) *testApp {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"), "test-secret-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := Config{
		BaseURL: baseURL, Pool: netip.MustParsePrefix("10.77.0.0/16"),
		Settings:   cookbook.Settings{Endpoint: "203.0.113.1:51820", ServerPublicKey: "x", MTU: 1380, Keepalive: 25},
		SignupMode: "open", MaxNetworksPerUser: 3, ShareTTL: time.Hour,
	}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := New(cfg, st, &wg.Fake{}, nil, webassets.FS)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return &testApp{t: t, ts: ts, srv: srv}
}

// client returns a browser-like client: cookie jar, no redirect following.
func (a *testApp) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (a *testApp) post(c *http.Client, path string, form url.Values) (*http.Response, string) {
	a.t.Helper()
	req, _ := http.NewRequest("POST", a.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", a.ts.URL)
	res, err := c.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

func (a *testApp) get(c *http.Client, path string) (*http.Response, string) {
	a.t.Helper()
	res, err := c.Get(a.ts.URL + path)
	if err != nil {
		a.t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

func (a *testApp) signup(c *http.Client, email, pw string) {
	a.t.Helper()
	res, body := a.post(c, "/signup", url.Values{"email": {email}, "password": {pw}})
	if res.StatusCode != http.StatusSeeOther {
		a.t.Fatalf("signup: %d %s", res.StatusCode, body)
	}
}

func TestLoginLockout(t *testing.T) {
	a := newTestApp(t, "http://example.test")
	a.signup(a.client(), "anna@example.org", "correct horse battery")
	c := a.client()
	for i := 0; i < 10; i++ {
		res, _ := a.post(c, "/login", url.Values{"email": {"anna@example.org"}, "password": {"wrong"}})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, res.StatusCode)
		}
	}
	res, body := a.post(c, "/login", url.Values{"email": {"Anna@Example.org"}, "password": {"correct horse battery"}})
	if res.StatusCode != http.StatusTooManyRequests || !strings.Contains(body, "Too many failed attempts") || res.Header.Get("Retry-After") == "" {
		t.Fatalf("expected lockout even with the right password, got %d", res.StatusCode)
	}
	// Other accounts are unaffected.
	a.signup(a.client(), "ben@example.org", "another good password")
	if res, _ := a.post(a.client(), "/login", url.Values{"email": {"ben@example.org"}, "password": {"another good password"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("other account blocked: %d", res.StatusCode)
	}
}

func TestPasswordLimits(t *testing.T) {
	a := newTestApp(t, "http://example.test")
	res, body := a.post(a.client(), "/signup", url.Values{"email": {"long@example.org"}, "password": {strings.Repeat("x", 100)}})
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "at most 72") {
		t.Fatalf("long password: %d", res.StatusCode)
	}
	a.signup(a.client(), "ok@example.org", "a fine password")
	if res, _ := a.post(a.client(), "/login", url.Values{"email": {"ok@example.org"}, "password": {strings.Repeat("y", 200)}}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("overlong login should be a normal failure, got %d", res.StatusCode)
	}
}

func TestFriendly404AndHSTS(t *testing.T) {
	a := newTestApp(t, "https://privnet.example")
	res, body := a.get(a.client(), "/definitely/not/here")
	if res.StatusCode != http.StatusNotFound || !strings.Contains(body, "Page not found") || !strings.Contains(body, `class="topbar"`) {
		t.Fatalf("404 page: %d", res.StatusCode)
	}
	if res.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("missing HSTS on https deployment")
	}
	b := newTestApp(t, "http://localhost:8080")
	if res, _ := b.get(b.client(), "/"); res.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be sent for plain-http deployments")
	}
}

func TestDuplicateDeviceName(t *testing.T) {
	a := newTestApp(t, "http://example.test")
	c := a.client()
	a.signup(c, "anna@example.org", "correct horse battery")
	if res, _ := a.post(c, "/networks", url.Values{"name": {"Home"}, "clients": {"5"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("create network: %d", res.StatusCode)
	}
	if res, _ := a.post(c, "/networks/1/devices", url.Values{"name": {"My Laptop"}, "platform": {"linux"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("first device: %d", res.StatusCode)
	}
	res, body := a.post(c, "/networks/1/devices", url.Values{"name": {"my laptop "}, "platform": {"linux"}})
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "already a device named") || !strings.Contains(body, `value="my laptop"`) {
		t.Fatalf("duplicate name: %d", res.StatusCode)
	}
}

func TestShareTokenGuessingIsLimited(t *testing.T) {
	a := newTestApp(t, "http://example.test")
	c := a.client()
	var last int
	for i := 0; i < 32; i++ {
		res, _ := a.get(c, "/join/not-a-real-token-"+strings.Repeat("a", i))
		last = res.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after many invalid tokens, got %d", last)
	}
}

func TestJoinStatus(t *testing.T) {
	a := newTestApp(t, "http://example.test")
	c := a.client()
	a.signup(c, "anna@example.org", "correct horse battery")
	a.post(c, "/networks", url.Values{"name": {"Home"}, "clients": {"5"}})
	a.post(c, "/networks/1/devices", url.Values{"name": {"phone"}, "platform": {"ios"}})
	_, body := a.post(c, "/devices/1/shares", nil)
	i := strings.Index(body, "/join/")
	if i < 0 {
		t.Fatal("no share link rendered")
	}
	tok := body[i+6 : i+6+strings.IndexByte(body[i+6:], '"')]
	anon := a.client()
	res, js := a.get(anon, "/join/"+tok+"/status")
	if res.StatusCode != 200 || !strings.Contains(js, `"id":1`) || !strings.Contains(js, `"online":`) {
		t.Fatalf("join status: %d %s", res.StatusCode, js)
	}
	if strings.Contains(js, "endpoint\":\"") && !strings.Contains(js, `"endpoint":""`) {
		t.Fatal("join status must not reveal the endpoint")
	}
	_, page := a.get(anon, "/join/"+tok)
	if !strings.Contains(page, `data-device-status="/join/`+tok+`/status"`) {
		t.Fatal("join page does not poll its status")
	}
	if res, _ := a.get(anon, "/join/bogus-token/status"); res.StatusCode != 404 {
		t.Fatalf("bogus token: %d", res.StatusCode)
	}
}

func TestRename(t *testing.T) {
	a := newTestApp(t, "http://example.test")
	c := a.client()
	a.signup(c, "anna@example.org", "correct horse battery")
	a.post(c, "/networks", url.Values{"name": {"Hmoe"}, "clients": {"5"}})
	a.post(c, "/networks/1/devices", url.Values{"name": {"lpatop"}, "platform": {"linux"}})
	a.post(c, "/networks/1/devices", url.Values{"name": {"phone"}, "platform": {"ios"}})
	if res, _ := a.post(c, "/networks/1/rename", url.Values{"name": {"Home"}}); !strings.Contains(res.Header.Get("Location"), "done=renamed") {
		t.Fatalf("network rename: %v", res.Header)
	}
	if res, _ := a.post(c, "/devices/1/rename", url.Values{"name": {"laptop"}}); !strings.Contains(res.Header.Get("Location"), "done=renamed") {
		t.Fatalf("device rename: %v", res.Header)
	}
	if res, _ := a.post(c, "/devices/1/rename", url.Values{"name": {"Phone"}}); !strings.Contains(res.Header.Get("Location"), "done=rename-invalid") {
		t.Fatal("duplicate rename accepted")
	}
	if res, _ := a.post(c, "/devices/1/rename", url.Values{"name": {"   "}}); !strings.Contains(res.Header.Get("Location"), "done=rename-invalid") {
		t.Fatal("empty rename accepted")
	}
	_, page := a.get(c, "/devices/1")
	if !strings.Contains(page, "<h1>laptop</h1>") || !strings.Contains(page, "lpatop.") {
		t.Fatal("rename should change the name but keep the hostname")
	}
	other := a.client()
	a.signup(other, "eve@example.org", "eve password 123")
	if res, _ := a.post(other, "/devices/1/rename", url.Values{"name": {"pwned"}}); res.StatusCode != 404 {
		t.Fatalf("other user could rename: %d", res.StatusCode)
	}
}

func TestAccountPasswordAndDelete(t *testing.T) {
	a := newTestApp(t, "http://example.test")
	c, other := a.client(), a.client()
	a.signup(c, "anna@example.org", "correct horse battery")
	a.post(other, "/login", url.Values{"email": {"anna@example.org"}, "password": {"correct horse battery"}})
	a.post(c, "/networks", url.Values{"name": {"Home"}, "clients": {"5"}})
	a.post(c, "/networks/1/devices", url.Values{"name": {"laptop"}, "platform": {"linux"}})

	if res, body := a.post(c, "/account/password", url.Values{"current": {"wrong"}, "new": {"a brand new password"}}); res.StatusCode != 401 || !strings.Contains(body, "not correct") {
		t.Fatalf("wrong current password: %d", res.StatusCode)
	}
	if res, _ := a.post(c, "/account/password", url.Values{"current": {"correct horse battery"}, "new": {"short"}}); res.StatusCode != 400 {
		t.Fatalf("short new password: %d", res.StatusCode)
	}
	res, _ := a.post(c, "/account/password", url.Values{"current": {"correct horse battery"}, "new": {"a brand new password"}})
	if !strings.Contains(res.Header.Get("Location"), "done=password-changed") {
		t.Fatalf("change password: %d %v", res.StatusCode, res.Header)
	}
	if res, _ := a.get(c, "/networks"); res.StatusCode != 200 {
		t.Fatal("current session should stay signed in")
	}
	if res, _ := a.get(other, "/networks"); res.StatusCode != http.StatusSeeOther {
		t.Fatal("other session should be signed out after a password change")
	}

	if res, _ := a.post(c, "/account/delete", url.Values{"confirm": {"someone@else"}, "password": {"a brand new password"}}); res.StatusCode != 400 {
		t.Fatalf("wrong confirmation: %d", res.StatusCode)
	}
	res, _ = a.post(c, "/account/delete", url.Values{"confirm": {"anna@example.org"}, "password": {"a brand new password"}})
	if !strings.Contains(res.Header.Get("Location"), "done=account-deleted") {
		t.Fatalf("delete account: %d", res.StatusCode)
	}
	if res, _ := a.post(a.client(), "/login", url.Values{"email": {"anna@example.org"}, "password": {"a brand new password"}}); res.StatusCode != 401 {
		t.Fatalf("deleted account can still log in: %d", res.StatusCode)
	}
	if nets, _ := a.srv.store.AllNetworks(context.Background()); len(nets) != 0 {
		t.Fatalf("networks left after account deletion: %d", len(nets))
	}
}

func TestAddAnotherDeviceOffer(t *testing.T) {
	a := newTestApp(t, "http://example.test")
	c := a.client()
	a.signup(c, "anna@example.org", "correct horse battery")
	a.post(c, "/networks", url.Values{"name": {"Home"}, "clients": {"4"}})
	for i, name := range []string{"one", "two", "three", "four"} {
		a.post(c, "/networks/1/devices", url.Values{"name": {name}, "platform": {"linux"}})
		_, page := a.get(c, fmt.Sprintf("/devices/%d?new=1", i+1))
		offered := strings.Contains(page, "Add another device")
		if want := i < 3; offered != want {
			t.Fatalf("device %d: offer=%v want %v", i+1, offered, want)
		}
	}
	if res, _ := a.get(c, "/api/networks/1/status"); res.StatusCode != 200 {
		t.Fatal("status api")
	}
	if res, _ := a.get(a.client(), "/api/networks/1/status"); res.StatusCode != 401 {
		t.Fatalf("anonymous status api should be 401 (the UI relies on it), got %d", res.StatusCode)
	}
}

func TestDeleteNetworkNamespace(t *testing.T) {
	a := newTestApp(t, "http://example.test", func(c *Config) {
		c.DNS = DNSConfig{Zone: "ip.example.test", Nameserver: "ns.example.test", MaxZonesPerUser: 3, MaxRecordsPerZone: 10}
	})
	c := a.client()
	a.signup(c, "anna@example.org", "correct horse battery")
	a.post(c, "/networks", url.Values{"name": {"Home"}, "clients": {"5"}})
	a.post(c, "/networks/1/devices", url.Values{"name": {"laptop"}, "platform": {"linux"}})
	ctx := context.Background()
	z, err := a.srv.store.DNSZoneByNetwork(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, page := a.get(c, fmt.Sprintf("/dns/%d", z.ID))
	if !strings.Contains(page, "Delete namespace") {
		t.Fatal("network namespace page should offer deletion")
	}

	// Another user can't delete it, and a wrong confirmation keeps it.
	other := a.client()
	a.signup(other, "eve@example.org", "eve password 123")
	if res, _ := a.post(other, fmt.Sprintf("/dns/%d/delete", z.ID), url.Values{"confirm": {z.Label}}); res.StatusCode != 404 {
		t.Fatalf("other user: %d", res.StatusCode)
	}
	a.post(c, fmt.Sprintf("/dns/%d/delete", z.ID), url.Values{"confirm": {"nope"}})
	if _, err := a.srv.store.DNSZoneByNetwork(ctx, 1); err != nil {
		t.Fatal("wrong confirmation deleted the namespace")
	}

	res, _ := a.post(c, fmt.Sprintf("/dns/%d/delete", z.ID), url.Values{"confirm": {z.Label}})
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "/networks/1") || !strings.Contains(loc, "done=dns-off") {
		t.Fatalf("delete redirect: %q", loc)
	}
	if _, err := a.srv.store.DNSZoneByNetwork(ctx, 1); err != store.ErrNotFound {
		t.Fatalf("namespace still there: %v", err)
	}
	// Startup backfill must not bring it back.
	if err := a.srv.EnsureNetworkZones(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.srv.store.DNSZoneByNetwork(ctx, 1); err != store.ErrNotFound {
		t.Fatal("backfill recreated a deleted namespace")
	}
	if res, page := a.get(c, "/networks/1"); res.StatusCode != 200 || !strings.Contains(page, "Turn on DNS names") {
		t.Fatalf("network page without DNS: %d", res.StatusCode)
	}
	if res, page := a.get(c, "/devices/1"); res.StatusCode != 200 || strings.Contains(page, "Add an HTTPS name") {
		t.Fatalf("device page without DNS: %d", res.StatusCode)
	}

	res, _ = a.post(c, "/networks/1/dns", nil)
	if !strings.Contains(res.Header.Get("Location"), "done=dns-on") {
		t.Fatalf("enable redirect: %v", res.Header)
	}
	z2, err := a.srv.store.DNSZoneByNetwork(ctx, 1)
	if err != nil || z2.Label == z.Label {
		t.Fatalf("expected a fresh namespace, got %v %v", z2, err)
	}
}
