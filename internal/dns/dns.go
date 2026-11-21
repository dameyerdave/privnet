// Package dns is a small authoritative DNS server for magic private-IP names
// (like nip.io) scoped to per-owner namespaces, plus ACME DNS-01 TXT records.
//
// Under the zone (e.g. ip.kizy.ch) every name has the form
//
//	<host>.<namespace>.<zone>
//
// where <namespace> belongs to exactly one user. <host> may be
//
//	10-77-0-2              dashed IPv4           -> 10.77.0.2
//	app-10-77-0-2          prefix + dashed IPv4  -> 10.77.0.2 (fits under a *.ns wildcard cert)
//	anything.10-77-0-2     nip.io style          -> 10.77.0.2
//	10.77.0.2              dotted IPv4           -> 10.77.0.2
//	anna-laptop            device / custom record of the namespace
//
// Only private addresses are ever answered. _acme-challenge.<anything>.<namespace>
// returns the namespace's current ACME TXT values, which only the namespace
// owner can set. The server never recurses.
package dns

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
)

// Zone is everything the server knows about one namespace.
type Zone struct {
	Label string
	Hosts map[string]netip.Addr // device hostnames, "gateway" and custom records
	TXT   []string              // newest first
}

// Snapshot is an immutable view of all namespaces, swapped atomically.
type Snapshot struct {
	Zones map[string]*Zone
}

type Config struct {
	Zone        string     // e.g. "ip.kizy.ch"
	Nameservers []string   // FQDNs that are authoritative for Zone
	NSAddr      netip.Addr // address of in-zone nameservers (glue), optional
	Hostmaster  string     // SOA RNAME as a name, e.g. "hostmaster.ip.kizy.ch"
	CAAIssuer   string     // e.g. "letsencrypt.org"; empty disables CAA
}

const (
	ttlA   = 300
	ttlTXT = 30
	ttlNeg = 60
	ttlNS  = 3600
)

type Server struct {
	cfg    Config
	zone   string // canonical, lower-case FQDN with trailing dot
	snap   atomic.Pointer[Snapshot]
	serial atomic.Uint32
}

func New(cfg Config) *Server {
	s := &Server{cfg: cfg, zone: mdns.CanonicalName(cfg.Zone)}
	s.snap.Store(&Snapshot{Zones: map[string]*Zone{}})
	s.serial.Store(uint32(time.Now().Unix()))
	return s
}

// Update installs a new snapshot and bumps the SOA serial.
func (s *Server) Update(sn *Snapshot) {
	s.snap.Store(sn)
	next := uint32(time.Now().Unix())
	if cur := s.serial.Load(); next <= cur {
		next = cur + 1
	}
	s.serial.Store(next)
}

// Zone returns the configured zone without trailing dot.
func (s *Server) ZoneName() string { return strings.TrimSuffix(s.zone, ".") }

var (
	dashedIP = regexp.MustCompile(`^(?:[a-z0-9-]*-)?(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})$`)
	octet    = regexp.MustCompile(`^\d{1,3}$`)
)

var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT / overlay networks
	netip.MustParsePrefix("127.0.0.0/8"),
}

// IsPrivate reports whether the address may be published by this service.
func IsPrivate(a netip.Addr) bool {
	for _, p := range privatePrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseOctets(parts []string) (netip.Addr, bool) {
	var b [4]byte
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 || (len(p) > 1 && p[0] == '0') {
			return netip.Addr{}, false
		}
		b[i] = byte(n)
	}
	return netip.AddrFrom4(b), true
}

// ParseHost resolves the host labels (left of the namespace) to an address
// using only the name itself (no records).
func ParseHost(labels []string) (netip.Addr, bool) {
	n := len(labels)
	if n == 0 {
		return netip.Addr{}, false
	}
	// dotted: last four labels are octets
	if n >= 4 {
		ok := true
		for _, l := range labels[n-4:] {
			if !octet.MatchString(l) {
				ok = false
				break
			}
		}
		if ok {
			return parseOctets(labels[n-4:])
		}
	}
	if m := dashedIP.FindStringSubmatch(labels[n-1]); m != nil {
		return parseOctets(m[1:])
	}
	return netip.Addr{}, false
}

// Answer kinds returned by Lookup.
type Kind int

const (
	Refused   Kind = iota // outside our zone
	NXDomain              // namespace does not exist
	NoData                // name exists (or may exist) but has no record of that type
	Apex                  // the zone apex
	NSHost                // an in-zone nameserver host
	Address               // an A record
	Challenge             // an _acme-challenge name
)

type Result struct {
	Kind      Kind
	Addr      netip.Addr
	Namespace *Zone
}

// Lookup classifies a query name. name may be any case, with or without a trailing dot.
func (s *Server) Lookup(name string) Result {
	q := mdns.CanonicalName(name)
	if q == s.zone {
		return Result{Kind: Apex}
	}
	if !strings.HasSuffix(q, "."+s.zone) {
		return Result{Kind: Refused}
	}
	for _, ns := range s.cfg.Nameservers {
		if mdns.CanonicalName(ns) == q && s.cfg.NSAddr.IsValid() {
			return Result{Kind: NSHost, Addr: s.cfg.NSAddr}
		}
	}
	rel := strings.TrimSuffix(q, "."+s.zone)
	labels := strings.Split(rel, ".")
	nsLabel := labels[len(labels)-1]
	host := labels[:len(labels)-1]
	z := s.snap.Load().Zones[nsLabel]
	if z == nil {
		return Result{Kind: NXDomain}
	}
	if len(host) > 0 && host[0] == "_acme-challenge" {
		return Result{Kind: Challenge, Namespace: z}
	}
	if len(host) == 1 {
		if a, ok := z.Hosts[host[0]]; ok {
			return Result{Kind: Address, Addr: a, Namespace: z}
		}
	}
	if a, ok := ParseHost(host); ok && IsPrivate(a) {
		return Result{Kind: Address, Addr: a, Namespace: z}
	}
	// Never NXDOMAIN inside an existing namespace: resolvers that implement
	// RFC 8020 (e.g. Unbound, used by Let's Encrypt) would then also treat
	// _acme-challenge.<name> as non-existent.
	return Result{Kind: NoData, Namespace: z}
}

func (s *Server) soa() mdns.RR {
	ns := "ns.invalid."
	if len(s.cfg.Nameservers) > 0 {
		ns = mdns.Fqdn(s.cfg.Nameservers[0])
	}
	return &mdns.SOA{
		Hdr:     mdns.RR_Header{Name: s.zone, Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: ttlNeg},
		Ns:      ns,
		Mbox:    mdns.Fqdn(s.cfg.Hostmaster),
		Serial:  s.serial.Load(),
		Refresh: 3600, Retry: 600, Expire: 604800, Minttl: ttlNeg,
	}
}

func (s *Server) nsRecords() []mdns.RR {
	var out []mdns.RR
	for _, ns := range s.cfg.Nameservers {
		out = append(out, &mdns.NS{Hdr: mdns.RR_Header{Name: s.zone, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: ttlNS}, Ns: mdns.Fqdn(ns)})
	}
	return out
}

func (s *Server) glue() []mdns.RR {
	var out []mdns.RR
	if !s.cfg.NSAddr.IsValid() {
		return nil
	}
	for _, ns := range s.cfg.Nameservers {
		if strings.HasSuffix(mdns.CanonicalName(ns), "."+s.zone) {
			out = append(out, &mdns.A{Hdr: mdns.RR_Header{Name: mdns.Fqdn(ns), Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: ttlNS}, A: s.cfg.NSAddr.AsSlice()})
		}
	}
	return out
}

// ServeDNS implements mdns.Handler.
func (s *Server) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	m := new(mdns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.RecursionAvailable = false
	defer func() {
		size := mdns.MinMsgSize
		if o := r.IsEdns0(); o != nil {
			m.SetEdns0(min(o.UDPSize(), 1232), false)
			size = int(min(o.UDPSize(), 1232))
		}
		if w.RemoteAddr().Network() == "tcp" {
			size = mdns.MaxMsgSize
		}
		m.Truncate(size)
		_ = w.WriteMsg(m)
	}()

	if r.Opcode != mdns.OpcodeQuery || len(r.Question) != 1 {
		m.Rcode = mdns.RcodeNotImplemented
		return
	}
	q := r.Question[0]
	if q.Qclass != mdns.ClassINET {
		m.Rcode = mdns.RcodeRefused
		return
	}
	res := s.Lookup(q.Name)
	if res.Kind == Refused {
		m.Rcode = mdns.RcodeRefused
		return
	}
	m.Authoritative = true
	hdr := func(t uint16, ttl uint32) mdns.RR_Header {
		return mdns.RR_Header{Name: q.Name, Rrtype: t, Class: mdns.ClassINET, Ttl: ttl}
	}
	if q.Qtype == mdns.TypeANY { // RFC 8482: minimal answer, no amplification
		m.Answer = []mdns.RR{&mdns.HINFO{Hdr: hdr(mdns.TypeHINFO, ttlNeg), Cpu: "RFC8482"}}
		return
	}

	switch res.Kind {
	case NXDomain:
		m.Rcode = mdns.RcodeNameError
	case Apex:
		switch q.Qtype {
		case mdns.TypeSOA:
			m.Answer = []mdns.RR{s.soa()}
		case mdns.TypeNS:
			m.Answer = s.nsRecords()
			m.Extra = s.glue()
		case mdns.TypeCAA:
			if s.cfg.CAAIssuer != "" {
				m.Answer = []mdns.RR{
					&mdns.CAA{Hdr: hdr(mdns.TypeCAA, ttlNS), Tag: "issue", Value: s.cfg.CAAIssuer},
					&mdns.CAA{Hdr: hdr(mdns.TypeCAA, ttlNS), Tag: "issuewild", Value: s.cfg.CAAIssuer},
				}
			}
		}
	case NSHost:
		if q.Qtype == mdns.TypeA {
			m.Answer = []mdns.RR{&mdns.A{Hdr: hdr(mdns.TypeA, ttlNS), A: res.Addr.AsSlice()}}
		}
	case Address:
		if q.Qtype == mdns.TypeA {
			m.Answer = []mdns.RR{&mdns.A{Hdr: hdr(mdns.TypeA, ttlA), A: res.Addr.AsSlice()}}
		}
	case Challenge:
		if q.Qtype == mdns.TypeTXT {
			for _, v := range res.Namespace.TXT {
				m.Answer = append(m.Answer, &mdns.TXT{Hdr: hdr(mdns.TypeTXT, ttlTXT), Txt: []string{v}})
			}
		}
	}
	if (len(m.Answer) == 0 && m.Rcode == mdns.RcodeSuccess) || m.Rcode == mdns.RcodeNameError {
		m.Ns = []mdns.RR{s.soa()}
	}
}

// ListenAndServe serves UDP and TCP on addr until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	udp := &mdns.Server{Addr: addr, Net: "udp", Handler: s, UDPSize: 1232}
	tcp := &mdns.Server{Addr: addr, Net: "tcp", Handler: s, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	errc := make(chan error, 2)
	for _, srv := range []*mdns.Server{udp, tcp} {
		go func(srv *mdns.Server) { errc <- srv.ListenAndServe() }(srv)
	}
	slog.Info("dns listening", "addr", addr, "zone", s.ZoneName())
	select {
	case <-ctx.Done():
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return nil
	case err := <-errc:
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return errors.Join(errors.New("dns server stopped"), err)
	}
}
