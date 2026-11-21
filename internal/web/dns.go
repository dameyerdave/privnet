package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	pdns "github.com/dameyerdave/privnet/internal/dns"
	"github.com/dameyerdave/privnet/internal/ipam"
	"github.com/dameyerdave/privnet/internal/store"
)

// DNSConfig enables the private-IP DNS service. Zero value = disabled.
type DNSConfig struct {
	Zone              string // e.g. ip.kizy.ch
	Nameserver        string // e.g. privnet-ns.kizy.ch
	PublicIP          string // address of the nameserver (shown in setup docs)
	MaxZonesPerUser   int    // standalone namespaces per user
	MaxRecordsPerZone int
}

func (c DNSConfig) Enabled() bool { return c.Zone != "" }

var (
	labelRe   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$`)
	hostRe    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)
	dashedRe  = regexp.MustCompile(`\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$`)
	acmeTXTRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	reserved  = map[string]bool{"www": true, "ns": true, "ns1": true, "ns2": true, "api": true, "admin": true, "mail": true, "acme": true, "_acme-challenge": true}
)

func randomString(n int, alphabet string) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func newAPIKey() string {
	return randomString(40, "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
}

func randomSuffix() string { return randomString(4, "abcdefghjkmnpqrstuvwxyz23456789") }

func validLabel(l string) string {
	switch {
	case !labelRe.MatchString(l):
		return "Use 3–32 lowercase letters, digits or dashes, starting and ending with a letter or digit."
	case reserved[l]:
		return "This name is reserved."
	case dashedRe.MatchString(l):
		return "A namespace can't end in an IP address pattern."
	}
	return ""
}

// ensureNetworkZone creates the namespace of a network if it doesn't exist.
func (s *Server) ensureNetworkZone(ctx context.Context, n *store.Network) (*store.DNSZone, error) {
	if z, err := s.store.DNSZoneByNetwork(ctx, n.ID); err == nil {
		return z, nil
	} else if err != store.ErrNotFound {
		return nil, err
	}
	base := n.Slug
	if len(base) > 26 {
		base = strings.TrimRight(base[:26], "-")
	}
	for i := 0; i < 10; i++ {
		label := base + "-" + randomSuffix()
		if validLabel(label) != "" {
			label = "net-" + randomSuffix() + randomSuffix()
		}
		z := &store.DNSZone{UserID: n.UserID, Label: label, NetworkID: n.ID, APIUser: newUUID(), APIKey: newAPIKey()}
		if err := s.store.CreateDNSZone(ctx, z); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				continue
			}
			return nil, err
		}
		return z, nil
	}
	return nil, fmt.Errorf("could not allocate a DNS label for network %d", n.ID)
}

// EnsureNetworkZones backfills namespaces for networks created before DNS existed.
func (s *Server) EnsureNetworkZones(ctx context.Context) error {
	if !s.cfg.DNS.Enabled() {
		return nil
	}
	nets, err := s.store.AllNetworks(ctx)
	if err != nil {
		return err
	}
	for _, n := range nets {
		if _, err := s.ensureNetworkZone(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// dnsDomain returns "<label>.<zone>" for a network, or "" when DNS is off.
func (s *Server) dnsDomain(ctx context.Context, networkID int64) string {
	if !s.cfg.DNS.Enabled() {
		return ""
	}
	z, err := s.store.DNSZoneByNetwork(ctx, networkID)
	if err != nil {
		return ""
	}
	return z.Label + "." + s.cfg.DNS.Zone
}

// SyncDNS rebuilds the DNS snapshot from the database.
func (s *Server) SyncDNS(ctx context.Context) error {
	if s.dns == nil {
		return nil
	}
	zones, err := s.store.AllDNSZones(ctx)
	if err != nil {
		return err
	}
	recs, err := s.store.AllDNSRecords(ctx)
	if err != nil {
		return err
	}
	txts, err := s.store.AllDNSTXT(ctx)
	if err != nil {
		return err
	}
	nets, err := s.store.AllNetworks(ctx)
	if err != nil {
		return err
	}
	devs, err := s.store.AllDevices(ctx)
	if err != nil {
		return err
	}
	byNet := map[int64]*store.Network{}
	for _, n := range nets {
		byNet[n.ID] = n
	}
	byID := map[int64]*pdns.Zone{}
	snap := &pdns.Snapshot{Zones: map[string]*pdns.Zone{}}
	for _, z := range zones {
		pz := &pdns.Zone{Label: z.Label, Hosts: map[string]netip.Addr{}}
		snap.Zones[z.Label] = pz
		byID[z.ID] = pz
		if n := byNet[z.NetworkID]; n != nil {
			pz.Hosts["gateway"] = ipam.NewPlan(n.Subnet, n.MaxClients).Gateway
		}
	}
	for _, r := range recs {
		if pz := byID[r.ZoneID]; pz != nil {
			pz.Hosts[r.Name] = r.IP
		}
	}
	netZone := map[int64]*pdns.Zone{}
	for _, z := range zones {
		if z.NetworkID != 0 {
			netZone[z.NetworkID] = byID[z.ID]
		}
	}
	if s.certsEnabled() { // HTTPS names: the device itself, or the gateway for the proxy
		all, err := s.store.AllCerts(ctx)
		if err != nil {
			return err
		}
		devIP := map[int64]netip.Addr{}
		for _, d := range devs {
			devIP[d.ID] = d.IP
		}
		for _, c := range all {
			pz, n := netZone[c.NetworkID], byNet[c.NetworkID]
			if pz == nil || n == nil {
				continue
			}
			if c.Mode == store.CertProxy {
				pz.Hosts[c.Name] = ipam.NewPlan(n.Subnet, n.MaxClients).Gateway
			} else if ip, ok := devIP[c.DeviceID]; ok {
				pz.Hosts[c.Name] = ip
			}
		}
	}
	for _, d := range devs { // devices win over custom records
		if pz := netZone[d.NetworkID]; pz != nil {
			pz.Hosts[d.Hostname] = d.IP
		}
	}
	for _, t := range txts { // newest first
		if pz := byID[t.ZoneID]; pz != nil {
			pz.TXT = append(pz.TXT, t.Value)
		}
	}
	s.dns.Update(snap)
	return nil
}

// ---- pages ----

type zoneCard struct {
	*store.DNSZone
	Domain  string
	Network *store.Network
	Records int
}

type dnsListPage struct {
	Zones      []zoneCard
	Zone       string
	Error      string
	FormLabel  string
	Suggestion string
	CanCreate  bool
	Max        int
}

func (s *Server) dnsListData(r *http.Request) (*dnsListPage, error) {
	u := currentUser(r)
	zones, err := s.store.DNSZonesByUser(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	p := &dnsListPage{Zone: s.cfg.DNS.Zone, Max: s.cfg.DNS.MaxZonesPerUser, Suggestion: "home-" + randomSuffix()}
	standalone := 0
	for _, z := range zones {
		c := zoneCard{DNSZone: z, Domain: z.Label + "." + s.cfg.DNS.Zone}
		if z.NetworkID != 0 {
			c.Network, _ = s.store.Network(r.Context(), z.NetworkID)
		} else {
			standalone++
		}
		recs, _ := s.store.DNSRecordsByZone(r.Context(), z.ID)
		c.Records = len(recs)
		p.Zones = append(p.Zones, c)
	}
	p.CanCreate = standalone < s.cfg.DNS.MaxZonesPerUser
	return p, nil
}

func (s *Server) handleDNSList(w http.ResponseWriter, r *http.Request) {
	p, err := s.dnsListData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "dns", p)
}

func (s *Server) handleCreateDNSZone(w http.ResponseWriter, r *http.Request) {
	label := strings.ToLower(strings.TrimSpace(r.FormValue("label")))
	fail := func(msg string) {
		p, err := s.dnsListData(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		p.Error, p.FormLabel = msg, label
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "dns", p)
	}
	if msg := validLabel(label); msg != "" {
		fail(msg)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.dnsListData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !p.CanCreate {
		fail(fmt.Sprintf("You can own at most %d standalone namespaces.", s.cfg.DNS.MaxZonesPerUser))
		return
	}
	z := &store.DNSZone{UserID: currentUser(r).ID, Label: label, APIUser: newUUID(), APIKey: newAPIKey()}
	if err := s.store.CreateDNSZone(r.Context(), z); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			fail("That namespace is already taken. Try another name.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	if err := s.SyncDNS(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/dns/%d", z.ID), http.StatusSeeOther)
}

func (s *Server) ownedZone(r *http.Request) (*store.DNSZone, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, store.ErrNotFound
	}
	z, err := s.store.DNSZone(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if z.UserID != currentUser(r).ID {
		return nil, store.ErrNotFound
	}
	return z, nil
}

type hostRow struct {
	Name   string
	FQDN   string
	IP     netip.Addr
	Source string // device | gateway | record
	ID     int64
}

type zonePage struct {
	Z          *store.DNSZone
	Domain     string
	Zone       string
	Network    *store.Network
	Hosts      []hostRow
	TXT        []store.DNSTXT
	Examples   []hostRow
	APIBase    string
	Nameserver string
	PublicIP   string
	Error      string
	FormName   string
	FormIP     string
	ShowKey    bool
	CanAdd     bool
	MaxRecords int
}

func (s *Server) zonePageData(r *http.Request, z *store.DNSZone) (*zonePage, error) {
	ctx := r.Context()
	domain := z.Label + "." + s.cfg.DNS.Zone
	p := &zonePage{Z: z, Domain: domain, Zone: s.cfg.DNS.Zone, APIBase: strings.TrimRight(s.cfg.BaseURL, "/") + "/acme-dns",
		Nameserver: s.cfg.DNS.Nameserver, PublicIP: s.cfg.DNS.PublicIP, MaxRecords: s.cfg.DNS.MaxRecordsPerZone}
	exampleIP := netip.MustParseAddr("192.168.1.10")
	if z.NetworkID != 0 {
		n, err := s.store.Network(ctx, z.NetworkID)
		if err != nil {
			return nil, err
		}
		p.Network = n
		gw := ipam.NewPlan(n.Subnet, n.MaxClients).Gateway
		p.Hosts = append(p.Hosts, hostRow{Name: "gateway", FQDN: "gateway." + domain, IP: gw, Source: "gateway"})
		devs, err := s.store.DevicesByNetwork(ctx, n.ID)
		if err != nil {
			return nil, err
		}
		for _, d := range devs {
			p.Hosts = append(p.Hosts, hostRow{Name: d.Hostname, FQDN: d.Hostname + "." + domain, IP: d.IP, Source: "device", ID: d.ID})
		}
		if s.certsEnabled() {
			list, err := s.store.CertsByNetwork(ctx, n.ID)
			if err != nil {
				return nil, err
			}
			byDev := map[int64]*store.Device{}
			for _, d := range devs {
				byDev[d.ID] = d
			}
			for _, c := range list {
				ip, src := gw, "proxy"
				if c.Mode == store.CertDownload {
					if d := byDev[c.DeviceID]; d != nil {
						ip = d.IP
					}
					src = "https"
				}
				p.Hosts = append(p.Hosts, hostRow{Name: c.Name, FQDN: c.Name + "." + domain, IP: ip, Source: src, ID: c.DeviceID})
			}
		}
		exampleIP = ipam.NewPlan(n.Subnet, n.MaxClients).FirstHost
	}
	recs, err := s.store.DNSRecordsByZone(ctx, z.ID)
	if err != nil {
		return nil, err
	}
	for _, rc := range recs {
		p.Hosts = append(p.Hosts, hostRow{Name: rc.Name, FQDN: rc.Name + "." + domain, IP: rc.IP, Source: "record", ID: rc.ID})
	}
	p.CanAdd = len(recs) < s.cfg.DNS.MaxRecordsPerZone
	if p.TXT, err = s.store.DNSTXTByZone(ctx, z.ID); err != nil {
		return nil, err
	}
	dashed := strings.ReplaceAll(exampleIP.String(), ".", "-")
	p.Examples = []hostRow{
		{Name: "dashed", FQDN: dashed + "." + domain, IP: exampleIP},
		{Name: "prefixed", FQDN: "app-" + dashed + "." + domain, IP: exampleIP},
		{Name: "nip.io style", FQDN: "app." + dashed + "." + domain, IP: exampleIP},
		{Name: "dotted", FQDN: exampleIP.String() + "." + domain, IP: exampleIP},
	}
	return p, nil
}

func (s *Server) handleDNSZone(w http.ResponseWriter, r *http.Request) {
	z, err := s.ownedZone(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	p, err := s.zonePageData(r, z)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	p.ShowKey = r.URL.Query().Get("rotated") == "1"
	s.render(w, r, "dnszone", p)
}

func (s *Server) handleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, err := s.ownedZone(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	ipStr := strings.TrimSpace(r.FormValue("ip"))
	fail := func(msg string) {
		p, err := s.zonePageData(r, z)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		p.Error, p.FormName, p.FormIP = msg, name, ipStr
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "dnszone", p)
	}
	if !hostRe.MatchString(name) || name == "gateway" || reserved[name] || dashedRe.MatchString(name) {
		fail("Use a single name of up to 40 lowercase letters, digits or dashes (not an IP pattern, not “gateway”).")
		return
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil || !ip.Is4() || !pdns.IsPrivate(ip) {
		fail("Only private IPv4 addresses can be published: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or 127.0.0.0/8.")
		return
	}
	p, err := s.zonePageData(r, z)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !p.CanAdd {
		fail(fmt.Sprintf("A namespace can hold at most %d custom records.", s.cfg.DNS.MaxRecordsPerZone))
		return
	}
	for _, h := range p.Hosts {
		if h.Name == name {
			fail("That name is already in use in this namespace.")
			return
		}
	}
	if err := s.store.CreateDNSRecord(r.Context(), &store.DNSRecord{ZoneID: z.ID, Name: name, IP: ip}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.SyncDNS(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/dns/%d#names", z.ID), http.StatusSeeOther)
}

func (s *Server) handleDeleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, err := s.ownedZone(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	rid, _ := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err := s.store.DeleteDNSRecord(r.Context(), rid, z.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.SyncDNS(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/dns/%d#names", z.ID), http.StatusSeeOther)
}

func (s *Server) handleRotateDNSKey(w http.ResponseWriter, r *http.Request) {
	z, err := s.ownedZone(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	if err := s.store.SetDNSZoneKey(r.Context(), z.ID, newAPIKey()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/dns/%d?rotated=1#certs", z.ID), http.StatusSeeOther)
}

func (s *Server) handleDeleteDNSZone(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, err := s.ownedZone(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	if z.NetworkID != 0 {
		http.Error(w, "network namespaces are removed together with their network", http.StatusBadRequest)
		return
	}
	if r.FormValue("confirm") != z.Label {
		http.Redirect(w, r, fmt.Sprintf("/dns/%d#danger", z.ID), http.StatusSeeOther)
		return
	}
	if err := s.store.DeleteDNSZone(r.Context(), z.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.SyncDNS(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/dns", http.StatusSeeOther)
}

// ---- acme-dns compatible API ----
//
// POST /acme-dns/update   X-Api-User, X-Api-Key   {"subdomain": "<label>", "txt": "<43 chars>"}
// Supported by lego/Traefik (acme-dns), cert-manager (acmeDNS), acme.sh (dns_acmedns), caddy-dns/acmedns.

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleACMEUpdate(w http.ResponseWriter, r *http.Request) {
	user, key := r.Header.Get("X-Api-User"), r.Header.Get("X-Api-Key")
	z, err := s.store.DNSZoneByAPIUser(r.Context(), user)
	if err != nil || subtle.ConstantTimeCompare([]byte(z.APIKey), []byte(key)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "forbidden"})
		return
	}
	var body struct {
		Subdomain string `json:"subdomain"`
		TXT       string `json:"txt"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed_json_payload"})
		return
	}
	if body.Subdomain != z.Label && body.Subdomain != z.APIUser {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "forbidden"})
		return
	}
	if !acmeTXTRe.MatchString(body.TXT) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_txt"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.AddDNSTXT(r.Context(), z.ID, body.TXT); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if err := s.SyncDNS(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "dns_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"txt": body.TXT})
}

func (s *Server) handleACMERegister(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error": "registration_disabled",
		"hint":  "create a namespace at " + strings.TrimRight(s.cfg.BaseURL, "/") + "/dns and use its credentials",
	})
}
