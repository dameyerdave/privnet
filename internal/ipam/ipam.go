// Package ipam carves per-network subnets out of a global pool and hands out
// client addresses inside them.
//
// Layout of a network subnet (example 10.77.0.8/29 for 4 clients):
//
//	10.77.0.8   network address (unused)
//	10.77.0.9   gateway – the privnet WireGuard server
//	10.77.0.10  client slot 1
//	...         client slot N
//	10.77.0.15  broadcast (unused)
package ipam

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
)

const (
	MinClients = 4
	MaxClients = 16
)

var ErrPoolExhausted = errors.New("ip pool exhausted")
var ErrNetworkFull = errors.New("all client slots of this network are in use")

// PrefixFor returns the smallest prefix length whose subnet fits the gateway
// plus `clients` hosts (network and broadcast addresses excluded).
func PrefixFor(clients int) int {
	need := clients + 3 // network + gateway + broadcast
	hostBits := bits.Len(uint(need - 1))
	return 32 - hostBits
}

// Plan describes the address layout of one network.
type Plan struct {
	Subnet    netip.Prefix
	Gateway   netip.Addr
	FirstHost netip.Addr
	LastHost  netip.Addr
	Clients   int
}

func NewPlan(subnet netip.Prefix, clients int) Plan {
	gw := subnet.Addr().Next()
	first := gw.Next()
	last := first
	for i := 1; i < clients; i++ {
		last = last.Next()
	}
	return Plan{Subnet: subnet, Gateway: gw, FirstHost: first, LastHost: last, Clients: clients}
}

// Slots returns all client addresses of the plan in order.
func (p Plan) Slots() []netip.Addr {
	out := make([]netip.Addr, 0, p.Clients)
	a := p.FirstHost
	for i := 0; i < p.Clients; i++ {
		out = append(out, a)
		a = a.Next()
	}
	return out
}

// Size is the total number of addresses in the subnet.
func (p Plan) Size() int { return 1 << (32 - p.Subnet.Bits()) }

// Allocate finds the first aligned, free block of the required size in pool.
func Allocate(pool netip.Prefix, used []netip.Prefix, clients int) (netip.Prefix, error) {
	if clients < MinClients || clients > MaxClients {
		return netip.Prefix{}, fmt.Errorf("clients must be between %d and %d", MinClients, MaxClients)
	}
	bitsLen := PrefixFor(clients)
	if bitsLen < pool.Bits() {
		return netip.Prefix{}, ErrPoolExhausted
	}
	step := uint32(1) << (32 - bitsLen)
	start := addrToU32(pool.Masked().Addr())
	end := start + (uint32(1) << (32 - pool.Bits())) // exclusive (may wrap for /0, irrelevant here)
	for base := start; base < end && base >= start; base += step {
		cand := netip.PrefixFrom(u32ToAddr(base), bitsLen)
		free := true
		for _, u := range used {
			if u.Overlaps(cand) {
				free = false
				break
			}
		}
		if free {
			return cand, nil
		}
	}
	return netip.Prefix{}, ErrPoolExhausted
}

// NextFree returns the first client slot not contained in taken.
func (p Plan) NextFree(taken []netip.Addr) (netip.Addr, error) {
	set := make(map[netip.Addr]bool, len(taken))
	for _, t := range taken {
		set[t] = true
	}
	for _, s := range p.Slots() {
		if !set[s] {
			return s, nil
		}
	}
	return netip.Addr{}, ErrNetworkFull
}

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
