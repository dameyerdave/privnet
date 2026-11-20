// Package cookbook builds the fully-resolved onboarding data for one device:
// the wg-quick config plus every concrete value the step-by-step guides show.
package cookbook

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/dameyerdave/privnet/internal/ipam"
	"github.com/dameyerdave/privnet/internal/store"
)

// DomainSuffix is appended to hostnames in the generated hosts-file snippets.
const DomainSuffix = "privnet"

type Platform struct {
	Key   string
	Label string
	Short string
}

var Platforms = []Platform{
	{"linux", "Linux", "Linux"},
	{"macos", "macOS", "macOS"},
	{"windows", "Windows", "Windows"},
	{"ios", "iPhone / iPad", "iOS"},
	{"android", "Android", "Android"},
}

func ValidPlatform(k string) bool {
	for _, p := range Platforms {
		if p.Key == k {
			return true
		}
	}
	return false
}

func PlatformLabel(k string) string {
	for _, p := range Platforms {
		if p.Key == k {
			return p.Label
		}
	}
	return k
}

// Settings are hub-wide values that end up in every client config.
type Settings struct {
	Endpoint        string // host:port clients dial
	ServerPublicKey string
	MTU             int
	Keepalive       int
}

type PeerInfo struct {
	Name     string
	Hostname string
	FQDN     string
	IP       netip.Addr
	Platform string
	Self     bool
}

// Cookbook is the template context for a device onboarding page.
type Cookbook struct {
	Network      *store.Network
	Plan         ipam.Plan
	Device       *store.Device
	Settings     Settings
	Iface        string // e.g. pn-homelab
	ConfFile     string // e.g. pn-homelab.conf
	FQDN         string
	Peers        []PeerInfo // every device in the network including this one
	Others       []PeerInfo // every other device
	HasKey       bool       // false when the user brought their own private key
	Config       string     // complete wg-quick config
	HostsSnippet string
	EndpointHost string
	EndpointPort string
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify turns a display name into a DNS/interface-friendly label.
func Slugify(s string, max int) string {
	s = nonSlug.ReplaceAllString(strings.ToLower(s), "-")
	s = strings.Trim(s, "-")
	if len(s) > max {
		s = strings.TrimRight(s[:max], "-")
	}
	if s == "" {
		s = "net"
	}
	return s
}

// IfaceName returns a Linux-safe (<=15 chars) interface name for a network.
func IfaceName(networkSlug string) string {
	return "pn-" + Slugify(networkSlug, 12)
}

func FQDN(hostname, networkSlug string) string {
	return fmt.Sprintf("%s.%s.%s", hostname, networkSlug, DomainSuffix)
}

func Build(n *store.Network, devices []*store.Device, d *store.Device, set Settings) *Cookbook {
	cb := &Cookbook{
		Network:  n,
		Plan:     ipam.NewPlan(n.Subnet, n.MaxClients),
		Device:   d,
		Settings: set,
		Iface:    IfaceName(n.Slug),
		FQDN:     FQDN(d.Hostname, n.Slug),
		HasKey:   d.PrivateKey != "",
	}
	cb.ConfFile = cb.Iface + ".conf"
	if h, p, ok := strings.Cut(set.Endpoint, ":"); ok {
		cb.EndpointHost, cb.EndpointPort = h, p
	}
	var hosts strings.Builder
	fmt.Fprintf(&hosts, "# privnet network %q (%s)\n", n.Name, n.Subnet)
	fmt.Fprintf(&hosts, "%-15s %s\n", cb.Plan.Gateway, FQDN("gateway", n.Slug))
	for _, o := range devices {
		pi := PeerInfo{Name: o.Name, Hostname: o.Hostname, FQDN: FQDN(o.Hostname, n.Slug), IP: o.IP, Platform: o.Platform, Self: o.ID == d.ID}
		cb.Peers = append(cb.Peers, pi)
		if !pi.Self {
			cb.Others = append(cb.Others, pi)
		}
		fmt.Fprintf(&hosts, "%-15s %s %s\n", o.IP, pi.FQDN, o.Hostname)
	}
	cb.HostsSnippet = hosts.String()
	cb.Config = RenderConfig(n, d, set)
	return cb
}

// RenderConfig produces the wg-quick configuration for a device.
func RenderConfig(n *store.Network, d *store.Device, set Settings) string {
	plan := ipam.NewPlan(n.Subnet, n.MaxClients)
	priv := d.PrivateKey
	if priv == "" {
		priv = "<paste the private key you generated for this device>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# privnet · network %q (%s) · device %q\n", n.Name, n.Subnet, d.Name)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
	fmt.Fprintf(&b, "Address = %s/32\n", d.IP)
	fmt.Fprintf(&b, "MTU = %d\n", set.MTU)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "# privnet hub · gateway %s\n", plan.Gateway)
	fmt.Fprintf(&b, "PublicKey = %s\n", set.ServerPublicKey)
	if d.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", d.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", set.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", n.Subnet)
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", set.Keepalive)
	return b.String()
}
