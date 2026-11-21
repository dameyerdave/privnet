package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/netip"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/dameyerdave/privnet/internal/cookbook"
	"github.com/dameyerdave/privnet/internal/ipam"
	"github.com/dameyerdave/privnet/internal/store"
	"github.com/dameyerdave/privnet/internal/wg"
)

// ---- auth pages ----

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if s.loadUser(r) != nil {
		http.Redirect(w, r, "/networks", http.StatusSeeOther)
		return
	}
	s.render(w, r, "home", map[string]any{"Signup": s.cfg.SignupMode != "closed", "MinClients": ipam.MinClients, "MaxClients": ipam.MaxClients})
}

type authForm struct {
	Email, Error, Next string
	NeedCode, Closed   bool
}

func (s *Server) handleSignupForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "signup", authForm{NeedCode: s.cfg.SignupMode == "code", Closed: s.cfg.SignupMode == "closed"})
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	f := authForm{Email: strings.TrimSpace(r.FormValue("email")), NeedCode: s.cfg.SignupMode == "code", Closed: s.cfg.SignupMode == "closed"}
	pw := r.FormValue("password")
	fail := func(msg string) {
		f.Error = msg
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "signup", f)
	}
	switch {
	case f.Closed:
		fail("Sign-up is disabled on this instance.")
		return
	case f.NeedCode && r.FormValue("code") != s.cfg.SignupCode:
		fail("The invite code is not valid.")
		return
	}
	if a, err := mail.ParseAddress(f.Email); err != nil || a.Address != f.Email {
		fail("Please enter a valid email address.")
		return
	}
	if len(pw) < 10 {
		fail("Use a password with at least 10 characters.")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	u, err := s.store.CreateUser(r.Context(), f.Email, string(hash))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			fail("An account with this email already exists. Try logging in.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	if err := s.setSession(w, r, u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login", authForm{Next: r.URL.Query().Get("next"), Closed: s.cfg.SignupMode == "closed"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	f := authForm{Email: strings.TrimSpace(r.FormValue("email")), Next: r.FormValue("next"), Closed: s.cfg.SignupMode == "closed"}
	u, err := s.store.UserByEmail(r.Context(), f.Email)
	if err == nil {
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(r.FormValue("password")))
	} else {
		// equalise timing for unknown accounts
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BWX4Z3ZpBvFnD6eJpA9sO4u5XvJK"), []byte("x"))
	}
	if err != nil {
		f.Error = "Email or password is incorrect."
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login", f)
		return
	}
	if err := s.setSession(w, r, u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	next := f.Next
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/networks"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---- networks ----

type networkCard struct {
	*store.Network
	Plan    ipam.Plan
	Used    int
	Online  int
	Percent int
}

type networksPage struct {
	Networks   []networkCard
	Error      string
	FormName   string
	FormSize   int
	CanCreate  bool
	MaxPerUser int
	MinClients int
	MaxClients int
	Sizes      []sizeOption
}

type sizeOption struct {
	Clients int
	Prefix  int
	Total   int
}

func sizeOptions() []sizeOption {
	var out []sizeOption
	for c := ipam.MinClients; c <= ipam.MaxClients; c++ {
		p := ipam.PrefixFor(c)
		out = append(out, sizeOption{Clients: c, Prefix: p, Total: 1 << (32 - p)})
	}
	return out
}

func (s *Server) networksPageData(r *http.Request) (*networksPage, error) {
	u := currentUser(r)
	nets, err := s.store.NetworksByUser(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	status, _ := s.wg.Status()
	p := &networksPage{FormSize: 4, MaxPerUser: s.cfg.MaxNetworksPerUser, MinClients: ipam.MinClients, MaxClients: ipam.MaxClients, Sizes: sizeOptions()}
	for _, n := range nets {
		devs, err := s.store.DevicesByNetwork(r.Context(), n.ID)
		if err != nil {
			return nil, err
		}
		c := networkCard{Network: n, Plan: ipam.NewPlan(n.Subnet, n.MaxClients), Used: len(devs)}
		for _, d := range devs {
			if status[d.PublicKey].Online() {
				c.Online++
			}
		}
		c.Percent = c.Used * 100 / n.MaxClients
		p.Networks = append(p.Networks, c)
	}
	p.CanCreate = len(nets) < s.cfg.MaxNetworksPerUser
	return p, nil
}

func (s *Server) handleNetworks(w http.ResponseWriter, r *http.Request) {
	p, err := s.networksPageData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "networks", p)
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	name := strings.TrimSpace(r.FormValue("name"))
	size, _ := strconv.Atoi(r.FormValue("clients"))
	fail := func(msg string) {
		p, err := s.networksPageData(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		p.Error, p.FormName, p.FormSize = msg, name, size
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "networks", p)
	}
	if name == "" || len(name) > 40 {
		fail("Give your network a name (up to 40 characters).")
		return
	}
	if size < ipam.MinClients || size > ipam.MaxClients {
		fail(fmt.Sprintf("Choose between %d and %d clients.", ipam.MinClients, ipam.MaxClients))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := r.Context()
	mine, err := s.store.NetworksByUser(ctx, u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(mine) >= s.cfg.MaxNetworksPerUser {
		fail(fmt.Sprintf("You can own at most %d networks.", s.cfg.MaxNetworksPerUser))
		return
	}
	slug := cookbook.Slugify(name, 20)
	for _, n := range mine {
		if n.Slug == slug {
			fail("You already have a network with a similar name.")
			return
		}
	}
	all, err := s.store.AllNetworks(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	used := make([]netip.Prefix, 0, len(all))
	for _, n := range all {
		used = append(used, n.Subnet)
	}
	subnet, err := ipam.Allocate(s.cfg.Pool, used, size)
	if err != nil {
		fail("No address space left on this hub. Please contact the administrator.")
		return
	}
	n := &store.Network{UserID: u.ID, Name: name, Slug: slug, Subnet: subnet, MaxClients: size}
	if err := s.store.CreateNetwork(ctx, n); err != nil {
		s.serverError(w, r, err)
		return
	}
	if s.cfg.DNS.Enabled() {
		if _, err := s.ensureNetworkZone(ctx, n); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if err := s.Sync(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/networks/%d", n.ID), http.StatusSeeOther)
}

type deviceRow struct {
	*store.Device
	FQDN          string
	PlatformLabel string
	Status        wg.PeerStatus
}

type slotRow struct {
	IP     netip.Addr
	Device *deviceRow
}

type networkPage struct {
	Network   *store.Network
	Plan      ipam.Plan
	Iface     string
	Devices   []deviceRow
	Slots     []slotRow
	Free      int
	Platforms []cookbook.Platform
	Error     string
	FormName  string
	FormPlat  string
	Endpoint  string
	Gateway   string
	DNSZoneID int64
	DNSDomain string
}

func (s *Server) networkPageData(r *http.Request, n *store.Network) (*networkPage, error) {
	devs, err := s.store.DevicesByNetwork(r.Context(), n.ID)
	if err != nil {
		return nil, err
	}
	status, _ := s.wg.Status()
	plan := ipam.NewPlan(n.Subnet, n.MaxClients)
	domain := cookbook.HostDomain(n.Slug, s.dnsDomain(r.Context(), n.ID))
	p := &networkPage{Network: n, Plan: plan, Iface: cookbook.IfaceName(n.Slug), Platforms: cookbook.Platforms,
		Endpoint: s.cfg.Settings.Endpoint, FormPlat: "linux", Gateway: cookbook.FQDN("gateway", domain)}
	if s.cfg.DNS.Enabled() {
		if z, err := s.store.DNSZoneByNetwork(r.Context(), n.ID); err == nil {
			p.DNSZoneID, p.DNSDomain = z.ID, domain
		}
	}
	byIP := map[netip.Addr]*deviceRow{}
	for _, d := range devs {
		row := deviceRow{Device: d, FQDN: cookbook.FQDN(d.Hostname, domain), PlatformLabel: cookbook.PlatformLabel(d.Platform), Status: status[d.PublicKey]}
		p.Devices = append(p.Devices, row)
	}
	for i := range p.Devices {
		byIP[p.Devices[i].IP] = &p.Devices[i]
	}
	for _, ip := range plan.Slots() {
		p.Slots = append(p.Slots, slotRow{IP: ip, Device: byIP[ip]})
		if byIP[ip] == nil {
			p.Free++
		}
	}
	return p, nil
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	n, err := s.ownedNetwork(r, r.PathValue("id"))
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	p, err := s.networkPageData(r, n)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "network", p)
}

func (s *Server) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.ownedNetwork(r, r.PathValue("id"))
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	if r.FormValue("confirm") != n.Name {
		http.Redirect(w, r, fmt.Sprintf("/networks/%d#danger", n.ID), http.StatusSeeOther)
		return
	}
	if err := s.store.DeleteNetwork(r.Context(), n.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.Sync(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

type statusRow struct {
	ID            int64  `json:"id"`
	Online        bool   `json:"online"`
	LastHandshake string `json:"lastHandshake"`
	Endpoint      string `json:"endpoint"`
	Rx            string `json:"rx"`
	Tx            string `json:"tx"`
}

func (s *Server) handleNetworkStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.ownedNetwork(r, r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	devs, err := s.store.DevicesByNetwork(r.Context(), n.ID)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	status, _ := s.wg.Status()
	out := []statusRow{}
	for _, d := range devs {
		st := status[d.PublicKey]
		out = append(out, statusRow{ID: d.ID, Online: st.Online(), LastHandshake: timeAgo(st.LastHandshake), Endpoint: st.Endpoint, Rx: humanBytes(st.RxBytes), Tx: humanBytes(st.TxBytes)})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// ---- devices ----

func (s *Server) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := r.Context()
	n, err := s.ownedNetwork(r, r.PathValue("id"))
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	platform := r.FormValue("platform")
	byoKey := strings.TrimSpace(r.FormValue("public_key"))
	fail := func(msg string) {
		p, err := s.networkPageData(r, n)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		p.Error, p.FormName, p.FormPlat = msg, name, platform
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "network", p)
	}
	if name == "" || len(name) > 40 {
		fail("Give the device a name (up to 40 characters), e.g. “anna-laptop”.")
		return
	}
	if !cookbook.ValidPlatform(platform) {
		fail("Pick the platform of the device.")
		return
	}
	devs, err := s.store.DevicesByNetwork(ctx, n.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	taken := make([]netip.Addr, 0, len(devs))
	hostnames := map[string]bool{"gateway": true}
	for _, d := range devs {
		taken = append(taken, d.IP)
		hostnames[d.Hostname] = true
	}
	if cl, err := s.store.CertsByNetwork(ctx, n.ID); err == nil {
		for _, c := range cl {
			hostnames[c.Name] = true
		}
	}
	plan := ipam.NewPlan(n.Subnet, n.MaxClients)
	ip, err := plan.NextFree(taken)
	if err != nil {
		fail(fmt.Sprintf("All %d client slots are in use. Remove a device first.", n.MaxClients))
		return
	}
	base := cookbook.Slugify(name, 24)
	host := base
	for i := 2; hostnames[host]; i++ {
		host = fmt.Sprintf("%s-%d", base, i)
	}

	d := &store.Device{NetworkID: n.ID, Name: name, Hostname: host, Platform: platform, IP: ip}
	if byoKey != "" {
		k, err := wgtypes.ParseKey(byoKey)
		if err != nil {
			fail("That public key is not a valid WireGuard key (44 base64 characters).")
			return
		}
		d.PublicKey = k.String()
	} else {
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		d.PrivateKey, d.PublicKey = priv.String(), priv.PublicKey().String()
	}
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.PresharedKey = psk.String()
	if err := s.store.CreateDevice(ctx, d); err != nil {
		if strings.Contains(err.Error(), "public_key") {
			fail("That public key is already used by another device.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	if err := s.Sync(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/devices/%d?new=1", d.ID), http.StatusSeeOther)
}

func (s *Server) buildCookbook(r *http.Request, n *store.Network, d *store.Device) (*cookbook.Cookbook, error) {
	devs, err := s.store.DevicesByNetwork(r.Context(), n.ID)
	if err != nil {
		return nil, err
	}
	return cookbook.Build(n, devs, d, s.cfg.Settings, s.dnsDomain(r.Context(), n.ID)), nil
}

type devicePage struct {
	CB           *cookbook.Cookbook
	Platforms    []cookbook.Platform
	Status       wg.PeerStatus
	Shares       []*store.Share
	NewShareURL  string
	NewShareQR   string
	ShareTTL     string
	IsNew        bool
	Join         bool
	JoinToken    string
	ConfigURL    string
	QRURL        string
	AbsConfigURL string
	ExpiresAt    time.Time
	HTTPS        *certSection
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	s.renderDevice(w, r, http.StatusOK, nil)
}

// renderDevice renders the device page; mutate may adjust the page data
// (e.g. a form error) before rendering.
func (s *Server) renderDevice(w http.ResponseWriter, r *http.Request, code int, mutate func(*devicePage)) {
	d, n, err := s.ownedDevice(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	cb, err := s.buildCookbook(r, n, d)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	shares, err := s.store.SharesByDevice(r.Context(), d.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	status, _ := s.wg.Status()
	https, err := s.certSectionData(r.Context(), n, d)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	p := devicePage{
		CB: cb, Platforms: cookbook.Platforms, Status: status[d.PublicKey], Shares: shares,
		ShareTTL: humanDuration(s.cfg.ShareTTL), IsNew: r.URL.Query().Get("new") == "1",
		ConfigURL: fmt.Sprintf("/devices/%d/config", d.ID), QRURL: fmt.Sprintf("/devices/%d/qr.png", d.ID),
		HTTPS: https,
	}
	if mutate != nil {
		mutate(&p)
	}
	if code != http.StatusOK {
		w.WriteHeader(code)
	}
	s.render(w, r, "device", p)
}

func (s *Server) handleDeviceConfig(w http.ResponseWriter, r *http.Request) {
	d, n, err := s.ownedDevice(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	s.writeConfig(w, n, d)
}

func (s *Server) writeConfig(w http.ResponseWriter, n *store.Network, d *store.Device) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, cookbook.IfaceName(n.Slug)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(cookbook.RenderConfig(n, d, s.cfg.Settings)))
}

func (s *Server) writeQR(w http.ResponseWriter, r *http.Request, n *store.Network, d *store.Device) {
	if d.PrivateKey == "" {
		s.notFound(w, r)
		return
	}
	png, err := qrcode.Encode(cookbook.RenderConfig(n, d, s.cfg.Settings), qrcode.Medium, 512)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (s *Server) handleDeviceQR(w http.ResponseWriter, r *http.Request) {
	d, n, err := s.ownedDevice(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	s.writeQR(w, r, n, d)
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, n, err := s.ownedDevice(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	if err := s.store.DeleteDevice(r.Context(), d.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.Sync(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/networks/%d", n.ID), http.StatusSeeOther)
}

// ---- sharing ----

func (s *Server) handleCreateShare(w http.ResponseWriter, r *http.Request) {
	d, _, err := s.ownedDevice(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	tok := randomToken()
	if _, err := s.store.CreateShare(r.Context(), tok, d.ID, s.cfg.ShareTTL); err != nil {
		s.serverError(w, r, err)
		return
	}
	// The token is only stored hashed, so this is the one time it can be shown.
	shareURL := strings.TrimRight(s.cfg.BaseURL, "/") + "/join/" + tok
	s.renderDevice(w, r, http.StatusOK, func(p *devicePage) {
		p.NewShareURL, p.NewShareQR = shareURL, qrDataURI(shareURL)
	})
}

func (s *Server) handleRevokeShare(w http.ResponseWriter, r *http.Request) {
	d, _, err := s.ownedDevice(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	sid, _ := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err := s.store.DeleteShare(r.Context(), sid, d.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/devices/%d#share", d.ID), http.StatusSeeOther)
}

func (s *Server) shareLookup(r *http.Request) (*store.Share, *store.Device, *store.Network, error) {
	sh, err := s.store.ShareByToken(r.Context(), r.PathValue("token"))
	if err != nil {
		return nil, nil, nil, err
	}
	d, err := s.store.Device(r.Context(), sh.DeviceID)
	if err != nil {
		return nil, nil, nil, err
	}
	n, err := s.store.Network(r.Context(), d.NetworkID)
	return sh, d, n, err
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	sh, d, n, err := s.shareLookup(r)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderStatus(w, r, http.StatusNotFound, "Link expired", "This onboarding link is invalid, expired or was revoked. Ask the network owner for a new one.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	cb, err := s.buildCookbook(r, n, d)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	status, _ := s.wg.Status()
	tok := r.PathValue("token")
	s.render(w, r, "device", devicePage{
		CB: cb, Platforms: cookbook.Platforms, Status: status[d.PublicKey], Join: true, JoinToken: tok,
		ConfigURL: "/join/" + tok + "/config", QRURL: "/join/" + tok + "/qr.png", ExpiresAt: sh.ExpiresAt,
		AbsConfigURL: strings.TrimRight(s.cfg.BaseURL, "/") + "/join/" + tok + "/config",
	})
}

func (s *Server) handleJoinConfig(w http.ResponseWriter, r *http.Request) {
	_, d, n, err := s.shareLookup(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	s.writeConfig(w, n, d)
}

func (s *Server) handleJoinQR(w http.ResponseWriter, r *http.Request) {
	_, d, n, err := s.shareLookup(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	s.writeQR(w, r, n, d)
}
