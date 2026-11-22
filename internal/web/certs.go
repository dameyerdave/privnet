package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dameyerdave/privnet/internal/certs"
	"github.com/dameyerdave/privnet/internal/ipam"
	"github.com/dameyerdave/privnet/internal/store"
)

// CertsConfig enables per-device HTTPS certificates (requires DNS).
type CertsConfig struct {
	Enabled      bool
	MaxPerUser   int
	MaxPerDevice int
	Proxy        bool          // the hub's HTTPS proxy is running
	RenewBefore  time.Duration // renew when the certificate expires sooner than this
	RetryAfter   time.Duration // minimum pause between failed renewal attempts
	Staging      bool          // ACME directory is a staging CA (certificates are not trusted)
}

// EnableCerts wires the ACME issuer and the HTTPS proxy into the server.
func (s *Server) EnableCerts(cfg CertsConfig, issuer *certs.Issuer, proxy *certs.Proxy) {
	if !s.cfg.DNS.Enabled() || s.dns == nil {
		return
	}
	s.cfg.Certs = cfg
	s.issuer, s.proxy = issuer, proxy
	s.certQueue = make(chan int64, 256)
}

func (s *Server) certsEnabled() bool { return s.issuer != nil }

// certFQDN is <name>.<namespace>.<zone> of a certificate.
func (s *Server) certFQDN(c *store.Cert, label string) string {
	return c.Name + "." + label + "." + s.cfg.DNS.Zone
}

// ---- issuing & renewal ----

func (s *Server) enqueueCert(id int64) {
	select {
	case s.certQueue <- id:
	default:
		slog.Warn("certificate queue full", "cert", id)
	}
}

// RunCertWorker issues and renews certificates one at a time until ctx ends.
func (s *Server) RunCertWorker(ctx context.Context) {
	if !s.certsEnabled() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-s.certQueue:
			s.processCert(ctx, id)
		}
	}
}

// RenewCerts queues pending certificates (e.g. after a restart) and those due for renewal.
func (s *Server) RenewCerts(ctx context.Context) {
	if !s.certsEnabled() {
		return
	}
	all, err := s.store.AllCerts(ctx)
	if err != nil {
		slog.Warn("renew scan", "err", err)
		return
	}
	for _, c := range all {
		if s.certDue(c) {
			s.enqueueCert(c.ID)
		}
	}
}

func (s *Server) certDue(c *store.Cert) bool {
	switch c.Status {
	case store.CertPending:
		return true
	case store.CertIssued:
		if time.Until(c.NotAfter) > s.cfg.Certs.RenewBefore {
			return false
		}
		return c.LastError == "" || time.Since(c.AttemptedAt) > s.cfg.Certs.RetryAfter
	}
	return false // errors wait for the user to retry (protects the CA rate limits)
}

func (s *Server) processCert(ctx context.Context, id int64) {
	c, err := s.store.Cert(ctx, id)
	if err != nil || !s.certDue(c) {
		return
	}
	z, err := s.store.DNSZoneByNetwork(ctx, c.NetworkID)
	if err != nil {
		_ = s.store.SaveCertFailure(ctx, c.ID, "network has no DNS namespace")
		return
	}
	fqdn := s.certFQDN(c, z.Label)
	res, err := s.issuer.Issue(ctx, fqdn, z.Label)
	if err != nil {
		msg := err.Error()
		if len(msg) > 400 {
			msg = msg[:400] + "…"
		}
		slog.Warn("certificate failed", "name", fqdn, "err", msg)
		_ = s.store.SaveCertFailure(ctx, c.ID, msg)
		return
	}
	if err := s.store.SaveCertIssued(ctx, c.ID, res.KeyPEM, res.CertPEM, res.NotAfter); err != nil {
		slog.Error("save certificate", "name", fqdn, "err", err)
		return
	}
	if err := s.syncProxy(ctx); err != nil {
		slog.Warn("proxy sync", "err", err)
	}
}

// syncProxy rebuilds the HTTPS proxy routes from issued proxy-mode certificates.
func (s *Server) syncProxy(ctx context.Context) error {
	if s.proxy == nil {
		return nil
	}
	all, err := s.store.AllCerts(ctx)
	if err != nil {
		return err
	}
	var routes []*certs.Route
	for _, c := range all {
		if c.Mode != store.CertProxy || c.CertPEM == "" {
			continue
		}
		kp, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
		if err != nil {
			slog.Warn("proxy certificate", "cert", c.ID, "err", err)
			continue
		}
		n, err := s.store.Network(ctx, c.NetworkID)
		if err != nil {
			continue
		}
		d, err := s.store.Device(ctx, c.DeviceID)
		if err != nil {
			continue
		}
		z, err := s.store.DNSZoneByNetwork(ctx, c.NetworkID)
		if err != nil {
			continue
		}
		routes = append(routes, &certs.Route{
			Host: s.certFQDN(c, z.Label), Cert: &kp, Subnet: n.Subnet,
			Gateway: ipam.NewPlan(n.Subnet, n.MaxClients).Gateway,
			Backend: netip.AddrPortFrom(d.IP, uint16(c.BackendPort)), BackendTLS: c.BackendTLS,
		})
	}
	s.proxy.Update(routes)
	return nil
}

// ---- device page ----

type certView struct {
	*store.Cert
	FQDN      string
	URL       string // proxy mode: the HTTPS URL clients open
	Target    string // proxy mode: where the hub forwards to
	PointsTo  netip.Addr
	DaysLeft  int
	FetchBase string // download mode: token URL prefix for automated pulls
	FileBase  string // download mode: logged-in download prefix
}

type certSection struct {
	Enabled   bool
	Proxy     bool
	Staging   bool
	Suffix    string // .<namespace>.<zone>
	Gateway   netip.Addr
	DeviceIP  netip.Addr
	Certs     []certView
	Pending   bool
	CanAdd    bool
	Max       int
	Error     string
	FormName  string
	FormMode  string
	FormPort  string
	FormTLS   bool
	ShowToken int64 // cert whose fetch token was just rotated
}

func (s *Server) certSectionData(ctx context.Context, n *store.Network, d *store.Device) (*certSection, error) {
	cs := &certSection{Enabled: s.certsEnabled()}
	if !cs.Enabled {
		return cs, nil
	}
	z, err := s.store.DNSZoneByNetwork(ctx, n.ID)
	if errors.Is(err, store.ErrNotFound) {
		cs.Enabled = false // DNS names are off for this network
		return cs, nil
	} else if err != nil {
		return nil, err
	}
	plan := ipam.NewPlan(n.Subnet, n.MaxClients)
	cs.Proxy, cs.Staging, cs.Max = s.cfg.Certs.Proxy, s.cfg.Certs.Staging, s.cfg.Certs.MaxPerDevice
	cs.Suffix = "." + z.Label + "." + s.cfg.DNS.Zone
	cs.Gateway, cs.DeviceIP = plan.Gateway, d.IP
	cs.FormMode, cs.FormPort = store.CertDownload, "80"
	if cs.Proxy {
		cs.FormMode = store.CertProxy
	}
	list, err := s.store.CertsByDevice(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(s.cfg.BaseURL, "/")
	for _, c := range list {
		v := certView{Cert: c, FQDN: s.certFQDN(c, z.Label), PointsTo: d.IP}
		if c.Mode == store.CertProxy {
			v.PointsTo = plan.Gateway
			v.URL = "https://" + v.FQDN
			scheme := "http"
			if c.BackendTLS {
				scheme = "https"
			}
			v.Target = fmt.Sprintf("%s://%s:%d", scheme, d.IP, c.BackendPort)
		} else {
			v.FetchBase = base + "/certs/fetch/" + c.FetchToken
			v.FileBase = fmt.Sprintf("/devices/%d/certs/%d", d.ID, c.ID)
		}
		if !c.NotAfter.IsZero() {
			v.DaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
		}
		if c.Status == store.CertPending {
			cs.Pending = true
		}
		cs.Certs = append(cs.Certs, v)
	}
	cs.CanAdd = len(list) < s.cfg.Certs.MaxPerDevice
	return cs, nil
}

// zoneNameTaken reports whether name is already used in a network's namespace.
func (s *Server) zoneNameTaken(ctx context.Context, n *store.Network, name string) (bool, error) {
	if name == "gateway" {
		return true, nil
	}
	devs, err := s.store.DevicesByNetwork(ctx, n.ID)
	if err != nil {
		return false, err
	}
	for _, d := range devs {
		if d.Hostname == name {
			return true, nil
		}
	}
	list, err := s.store.CertsByNetwork(ctx, n.ID)
	if err != nil {
		return false, err
	}
	for _, c := range list {
		if c.Name == name {
			return true, nil
		}
	}
	z, err := s.store.DNSZoneByNetwork(ctx, n.ID)
	if err != nil {
		return false, err
	}
	recs, err := s.store.DNSRecordsByZone(ctx, z.ID)
	if err != nil {
		return false, err
	}
	for _, r := range recs {
		if r.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) handleCreateCert(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := r.Context()
	d, n, err := s.ownedDevice(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	mode := r.FormValue("mode")
	portStr := strings.TrimSpace(r.FormValue("port"))
	backendTLS := r.FormValue("backend_tls") == "1"
	fail := func(msg string) {
		s.renderDevice(w, r, http.StatusBadRequest, func(p *devicePage) {
			p.HTTPS.Error, p.HTTPS.FormName, p.HTTPS.FormMode, p.HTTPS.FormPort, p.HTTPS.FormTLS = msg, name, mode, portStr, backendTLS
		})
	}
	if !hostRe.MatchString(name) || reserved[name] || dashedRe.MatchString(name) {
		fail("Use a single name of up to 40 lowercase letters, digits or dashes, e.g. “nas” or “grafana” (not an IP pattern).")
		return
	}
	if mode != store.CertDownload && !(mode == store.CertProxy && s.cfg.Certs.Proxy) {
		fail("Pick how the certificate is used.")
		return
	}
	port := 0
	if mode == store.CertProxy {
		port, err = strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			fail("Enter the port the service listens on, on the device (1–65535).")
			return
		}
	}
	if n.DNSOff {
		fail("DNS names are off for this network. Turn them on on the network page first.")
		return
	}
	if taken, err := s.zoneNameTaken(ctx, n, name); err != nil {
		s.serverError(w, r, err)
		return
	} else if taken {
		fail("That name is already used in this network. Pick another one.")
		return
	}
	mine, err := s.store.CertsByDevice(ctx, d.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(mine) >= s.cfg.Certs.MaxPerDevice {
		fail(fmt.Sprintf("A device can have at most %d HTTPS names.", s.cfg.Certs.MaxPerDevice))
		return
	}
	if total, err := s.store.CountCertsByUser(ctx, n.UserID); err != nil {
		s.serverError(w, r, err)
		return
	} else if total >= s.cfg.Certs.MaxPerUser {
		fail(fmt.Sprintf("Your account can have at most %d HTTPS names. Remove one first.", s.cfg.Certs.MaxPerUser))
		return
	}
	c := &store.Cert{DeviceID: d.ID, NetworkID: n.ID, Name: name, Mode: mode, BackendPort: port, BackendTLS: backendTLS,
		Status: store.CertPending, FetchToken: newAPIKey()}
	if err := s.store.CreateCert(ctx, c); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			fail("That name is already used in this network. Pick another one.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	if err := s.SyncDNS(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.enqueueCert(c.ID)
	http.Redirect(w, r, fmt.Sprintf("/devices/%d#https", d.ID), http.StatusSeeOther)
}

func (s *Server) ownedCert(r *http.Request) (*store.Cert, *store.Device, error) {
	d, _, err := s.ownedDevice(r)
	if err != nil {
		return nil, nil, err
	}
	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil {
		return nil, nil, store.ErrNotFound
	}
	c, err := s.store.Cert(r.Context(), cid)
	if err != nil {
		return nil, nil, err
	}
	if c.DeviceID != d.ID {
		return nil, nil, store.ErrNotFound
	}
	return c, d, nil
}

func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, d, err := s.ownedCert(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	if err := s.store.DeleteCert(r.Context(), c.ID, d.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.SyncDNS(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.syncProxy(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	redirectDone(w, r, fmt.Sprintf("/devices/%d#https", d.ID), "cert-removed")
}

func (s *Server) handleRetryCert(w http.ResponseWriter, r *http.Request) {
	c, d, err := s.ownedCert(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	if c.Status == store.CertError {
		if err := s.store.SetCertPending(r.Context(), c.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.enqueueCert(c.ID)
	}
	http.Redirect(w, r, fmt.Sprintf("/devices/%d#https", d.ID), http.StatusSeeOther)
}

func (s *Server) handleRotateCertToken(w http.ResponseWriter, r *http.Request) {
	c, d, err := s.ownedCert(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	if err := s.store.SetCertFetchToken(r.Context(), c.ID, newAPIKey()); err != nil {
		s.serverError(w, r, err)
		return
	}
	redirectDone(w, r, fmt.Sprintf("/devices/%d#cert-%d", d.ID, c.ID), "token-rotated")
}

// writeCertFile serves fullchain.pem, cert.pem, chain.pem or privkey.pem of a
// download-mode certificate.
func writeCertFile(w http.ResponseWriter, c *store.Cert, file string) bool {
	if c.Mode != store.CertDownload || c.CertPEM == "" {
		return false
	}
	var body string
	switch file {
	case "fullchain.pem":
		body = c.CertPEM
	case "cert.pem", "chain.pem":
		blocks := strings.SplitAfter(c.CertPEM, "-----END CERTIFICATE-----\n")
		if file == "cert.pem" {
			body = blocks[0]
		} else {
			body = strings.Join(blocks[1:], "")
		}
	case "privkey.pem":
		body = c.KeyPEM
	default:
		return false
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s"`, c.Name, file))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Last-Modified", c.IssuedAt.UTC().Format(http.TimeFormat))
	_, _ = w.Write([]byte(body))
	return true
}

func (s *Server) handleCertFile(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.ownedCert(r)
	if err != nil {
		s.handleLookupErr(w, r, err)
		return
	}
	if !writeCertFile(w, c, r.PathValue("file")) {
		s.notFound(w, r)
	}
}

// handleCertFetch lets a device pull its renewed files with the secret token URL.
func (s *Server) handleCertFetch(w http.ResponseWriter, r *http.Request) {
	if s.tooManyTokens(w, r) {
		return
	}
	tok := r.PathValue("token")
	c, err := s.store.CertByFetchToken(r.Context(), tok)
	if err != nil || len(tok) < 32 {
		s.badToken(r)
		http.NotFound(w, r)
		return
	}
	if !writeCertFile(w, c, r.PathValue("file")) {
		http.NotFound(w, r)
	}
}
