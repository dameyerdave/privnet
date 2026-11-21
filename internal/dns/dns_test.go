package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func testServer() *Server {
	s := New(Config{Zone: "ip.kizy.ch", Nameservers: []string{"privnet-ns.kizy.ch"}, Hostmaster: "hostmaster.ip.kizy.ch", CAAIssuer: "letsencrypt.org"})
	s.Update(&Snapshot{Zones: map[string]*Zone{
		"home-x7k2": {Label: "home-x7k2", Hosts: map[string]netip.Addr{
			"anna-laptop": netip.MustParseAddr("10.77.0.2"),
			"nas":         netip.MustParseAddr("192.168.1.20"),
		}, TXT: []string{"tok-newest", "tok-older"}},
	}})
	return s
}

func TestLookup(t *testing.T) {
	s := testServer()
	cases := []struct {
		name string
		kind Kind
		addr string
	}{
		{"10-77-0-2.home-x7k2.ip.kizy.ch", Address, "10.77.0.2"},
		{"App-192-168-1-10.HOME-x7k2.ip.kizy.ch.", Address, "192.168.1.10"},
		{"web.172-16-5-4.home-x7k2.ip.kizy.ch", Address, "172.16.5.4"},
		{"10.1.2.3.home-x7k2.ip.kizy.ch", Address, "10.1.2.3"},
		{"x.100.64.0.1.home-x7k2.ip.kizy.ch", Address, "100.64.0.1"},
		{"anna-laptop.home-x7k2.ip.kizy.ch", Address, "10.77.0.2"},
		{"nas.home-x7k2.ip.kizy.ch", Address, "192.168.1.20"},
		{"8-8-8-8.home-x7k2.ip.kizy.ch", NoData, ""},    // public IPs are never answered
		{"10-0-0-256.home-x7k2.ip.kizy.ch", NoData, ""}, // invalid octet
		{"10-0-0-01.home-x7k2.ip.kizy.ch", NoData, ""},  // leading zero
		{"unknown.home-x7k2.ip.kizy.ch", NoData, ""},    // NODATA, not NXDOMAIN (RFC 8020)
		{"home-x7k2.ip.kizy.ch", NoData, ""},
		{"_acme-challenge.home-x7k2.ip.kizy.ch", Challenge, ""},
		{"_acme-challenge.nas.home-x7k2.ip.kizy.ch", Challenge, ""},
		{"10-0-0-1.nobody.ip.kizy.ch", NXDomain, ""},
		{"ip.kizy.ch", Apex, ""},
		{"example.com", Refused, ""},
		{"evilip.kizy.ch", Refused, ""},
	}
	for _, c := range cases {
		r := s.Lookup(c.name)
		if r.Kind != c.kind {
			t.Errorf("%s: kind %d, want %d", c.name, r.Kind, c.kind)
			continue
		}
		if c.addr != "" && r.Addr.String() != c.addr {
			t.Errorf("%s: addr %s, want %s", c.name, r.Addr, c.addr)
		}
	}
}

func TestServeDNS(t *testing.T) {
	s := testServer()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: s}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	time.Sleep(50 * time.Millisecond)
	addr := pc.LocalAddr().String()

	ask := func(name string, qt uint16) *mdns.Msg {
		m := new(mdns.Msg)
		m.SetQuestion(name, qt)
		m.SetEdns0(1232, false)
		c := &mdns.Client{Timeout: 2 * time.Second}
		r, _, err := c.ExchangeContext(context.Background(), m, addr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return r
	}

	r := ask("10-77-0-9.home-x7k2.ip.kizy.ch.", mdns.TypeA)
	if !r.Authoritative || len(r.Answer) != 1 || r.Answer[0].(*mdns.A).A.String() != "10.77.0.9" {
		t.Fatalf("A answer wrong: %v", r)
	}
	r = ask("_acme-challenge.home-x7k2.ip.kizy.ch.", mdns.TypeTXT)
	if len(r.Answer) != 2 || r.Answer[0].(*mdns.TXT).Txt[0] != "tok-newest" {
		t.Fatalf("TXT answer wrong: %v", r)
	}
	r = ask("10-1-1-1.nobody.ip.kizy.ch.", mdns.TypeA)
	if r.Rcode != mdns.RcodeNameError || len(r.Ns) != 1 {
		t.Fatalf("expected NXDOMAIN with SOA: %v", r)
	}
	r = ask("10-77-0-9.home-x7k2.ip.kizy.ch.", mdns.TypeAAAA)
	if r.Rcode != mdns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) != 1 {
		t.Fatalf("expected NODATA: %v", r)
	}
	r = ask("ip.kizy.ch.", mdns.TypeCAA)
	if len(r.Answer) != 2 {
		t.Fatalf("expected CAA: %v", r)
	}
	r = ask("google.com.", mdns.TypeA)
	if r.Rcode != mdns.RcodeRefused {
		t.Fatalf("expected REFUSED: %v", r)
	}
}
