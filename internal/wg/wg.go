// Package wg reconciles the WireGuard interface, routing and firewall of the
// privnet hub with the desired state stored in the database.
//
// All networks share one interface (wg0) and one UDP port. Isolation between
// networks is enforced with iptables: traffic is only forwarded wg0 -> wg0 when
// source and destination are inside the same network subnet. Nothing is
// forwarded or NATed to the cluster network.
package wg

import (
	"net/netip"
	"time"
)

// Peer is one client device.
type Peer struct {
	PublicKey    string
	PresharedKey string
	IP           netip.Addr
}

// Network is one isolated private network.
type Network struct {
	Subnet  netip.Prefix
	Gateway netip.Addr
}

// State is the full desired configuration of the hub.
type State struct {
	Networks []Network
	Peers    []Peer
}

// PeerStatus is runtime info reported by the kernel.
type PeerStatus struct {
	Endpoint      string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Online reports whether the peer completed a handshake recently. WireGuard
// re-handshakes every 2 minutes while traffic (or keepalive) flows.
func (p PeerStatus) Online() bool {
	return !p.LastHandshake.IsZero() && time.Since(p.LastHandshake) < 3*time.Minute
}

type Manager interface {
	// Apply makes the interface match the desired state (idempotent).
	Apply(State) error
	// Status returns runtime info keyed by base64 public key.
	Status() (map[string]PeerStatus, error)
}
