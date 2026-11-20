package ipam

import (
	"net/netip"
	"testing"
)

func TestPrefixFor(t *testing.T) {
	cases := map[int]int{4: 29, 5: 29, 6: 28, 13: 28, 14: 27, 16: 27}
	for clients, want := range cases {
		if got := PrefixFor(clients); got != want {
			t.Errorf("PrefixFor(%d) = /%d, want /%d", clients, got, want)
		}
		// sanity: the plan must fit inside the subnet
		size := 1 << (32 - want)
		if clients+3 > size {
			t.Errorf("%d clients do not fit /%d", clients, want)
		}
	}
}

func TestAllocateAndPlan(t *testing.T) {
	pool := netip.MustParsePrefix("10.77.0.0/16")
	var used []netip.Prefix

	a, err := Allocate(pool, used, 4)
	if err != nil || a.String() != "10.77.0.0/29" {
		t.Fatalf("first alloc = %v, %v", a, err)
	}
	used = append(used, a)

	b, _ := Allocate(pool, used, 16)
	if b.String() != "10.77.0.32/27" {
		t.Fatalf("second alloc = %v", b)
	}
	used = append(used, b)

	c, _ := Allocate(pool, used, 5)
	if c.String() != "10.77.0.8/29" {
		t.Fatalf("third alloc = %v", c)
	}

	p := NewPlan(a, 4)
	if p.Gateway.String() != "10.77.0.1" || p.FirstHost.String() != "10.77.0.2" || p.LastHost.String() != "10.77.0.5" {
		t.Fatalf("bad plan %+v", p)
	}
	n, _ := p.NextFree([]netip.Addr{netip.MustParseAddr("10.77.0.2")})
	if n.String() != "10.77.0.3" {
		t.Fatalf("next free = %v", n)
	}
	all := p.Slots()
	if _, err := p.NextFree(all); err != ErrNetworkFull {
		t.Fatalf("expected full, got %v", err)
	}

	p16 := NewPlan(b, 16)
	if p16.LastHost.String() != "10.77.0.49" {
		t.Fatalf("p16 last = %v", p16.LastHost)
	}
	if _, err := Allocate(pool, nil, 3); err == nil {
		t.Fatal("expected error for 3 clients")
	}
}
