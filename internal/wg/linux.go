package wg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Kernel drives a kernel WireGuard interface via netlink, iproute2 and iptables.
type Kernel struct {
	Iface      string
	ListenPort int
	MTU        int
	Pool       netip.Prefix
	PrivateKey wgtypes.Key

	mu     sync.Mutex
	client *wgctrl.Client
}

func NewKernel(iface string, port, mtu int, pool netip.Prefix, priv wgtypes.Key) (*Kernel, error) {
	k := &Kernel{Iface: iface, ListenPort: port, MTU: mtu, Pool: pool, PrivateKey: priv}
	if err := k.ensureLink(); err != nil {
		return nil, err
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	k.client = c
	return k, nil
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func runStdin(stdin, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func (k *Kernel) ensureLink() error {
	if _, err := net.InterfaceByName(k.Iface); err != nil {
		if _, err := run("ip", "link", "add", k.Iface, "type", "wireguard"); err != nil {
			return err
		}
		slog.Info("created wireguard interface", "iface", k.Iface)
	}
	if _, err := run("ip", "link", "set", k.Iface, "mtu", fmt.Sprint(k.MTU), "up"); err != nil {
		return err
	}
	// Route the whole pool into the tunnel; WireGuard picks the peer by /32 AllowedIPs.
	_, err := run("ip", "route", "replace", k.Pool.String(), "dev", k.Iface)
	return err
}

func (k *Kernel) Apply(st State) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if err := k.ensureLink(); err != nil {
		return err
	}
	if err := k.syncAddresses(st.Networks); err != nil {
		return err
	}

	peers := make([]wgtypes.PeerConfig, 0, len(st.Peers))
	for _, p := range st.Peers {
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peer %s: %w", p.IP, err)
		}
		pc := wgtypes.PeerConfig{
			PublicKey:         pub,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{{IP: p.IP.AsSlice(), Mask: net.CIDRMask(32, 32)}},
		}
		if p.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(p.PresharedKey)
			if err != nil {
				return fmt.Errorf("peer %s psk: %w", p.IP, err)
			}
			pc.PresharedKey = &psk
		}
		peers = append(peers, pc)
	}
	port := k.ListenPort
	if err := k.client.ConfigureDevice(k.Iface, wgtypes.Config{
		PrivateKey:   &k.PrivateKey,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers:        peers,
	}); err != nil {
		return fmt.Errorf("configure %s: %w", k.Iface, err)
	}
	return k.applyFirewall(st.Networks)
}

// syncAddresses assigns each network's gateway address to the interface so the
// hub answers pings, and removes addresses of deleted networks.
func (k *Kernel) syncAddresses(nets []Network) error {
	out, err := run("ip", "-j", "addr", "show", "dev", k.Iface)
	if err != nil {
		return err
	}
	var links []struct {
		AddrInfo []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		return fmt.Errorf("parse ip -j: %w", err)
	}
	have := map[string]bool{}
	for _, l := range links {
		for _, a := range l.AddrInfo {
			if a.Family == "inet" {
				have[fmt.Sprintf("%s/%d", a.Local, a.PrefixLen)] = true
			}
		}
	}
	want := map[string]bool{}
	for _, n := range nets {
		want[n.Gateway.String()+"/32"] = true
	}
	for a := range want {
		if !have[a] {
			if _, err := run("ip", "addr", "add", a, "dev", k.Iface); err != nil {
				return err
			}
		}
	}
	for a := range have {
		if !want[a] {
			if _, err := run("ip", "addr", "del", a, "dev", k.Iface); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyFirewall atomically replaces the filter table of the pod's network
// namespace. The pod owns this namespace exclusively, so a full restore is safe.
func (k *Kernel) applyFirewall(nets []Network) error {
	var b strings.Builder
	i := k.Iface
	b.WriteString("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n")
	// Clients may ping their gateway but cannot reach anything else on the hub
	// (e.g. the web UI listening on the pod IP).
	fmt.Fprintf(&b, "-A INPUT -i %s -p icmp --icmp-type echo-request -j ACCEPT\n", i)
	fmt.Fprintf(&b, "-A INPUT -i %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", i)
	// The HTTPS proxy: each network reaches only its own gateway on 80/443.
	for _, n := range nets {
		fmt.Fprintf(&b, "-A INPUT -i %s -s %s -d %s/32 -p tcp -m multiport --dports 80,443 -j ACCEPT\n", i, n.Subnet, n.Gateway)
	}
	fmt.Fprintf(&b, "-A INPUT -i %s -j DROP\n", i)
	// Only intra-network traffic is forwarded.
	for _, n := range nets {
		fmt.Fprintf(&b, "-A FORWARD -i %s -o %s -s %s -d %s -j ACCEPT\n", i, i, n.Subnet, n.Subnet)
	}
	b.WriteString("COMMIT\n")
	return runStdin(b.String(), "iptables-restore")
}

func (k *Kernel) Status() (map[string]PeerStatus, error) {
	dev, err := k.client.Device(k.Iface)
	if err != nil {
		return nil, err
	}
	out := make(map[string]PeerStatus, len(dev.Peers))
	for _, p := range dev.Peers {
		ps := PeerStatus{LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes}
		if p.Endpoint != nil {
			ps.Endpoint = p.Endpoint.String()
		}
		out[p.PublicKey.String()] = ps
	}
	return out, nil
}
