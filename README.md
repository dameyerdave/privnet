# privnet

Private WireGuard networks with a web UI: a small, self-hosted alternative to Tailscale.

You create a network, pick how many devices it should hold (4–16), and add devices. privnet:

- plans the address space (smallest aligned subnet from `10.77.0.0/16`),
- generates keys, a preshared key and a ready-to-use `wg-quick` config per device,
- authorises each device on the WireGuard hub immediately,
- shows a **QR code** for phones and a **step-by-step setup guide** for Linux, macOS, Windows, iOS and Android, with the device's real values (interface name, IPs, endpoint, keys, ping commands for every peer, hosts-file entries),
- creates **time-limited share links** so someone else can onboard their own device without an account,
- shows live online status, last handshake and traffic per device,
- runs a **private-IP DNS service** (like nip.io) under `ip.kizy.ch` with per-owner namespaces, so
  you can get **trusted Let's Encrypt certificates** for private IPs via DNS-01.

Live at **https://privnet.kizy.ch**. The WireGuard hub listens on **83.228.201.62:51820/udp**.

## Architecture

```
            HTTPS                                   UDP 51820
 browser ──────────▶ Cloudflare ─▶ cloudflared ─▶ Traefik ─▶ privnet-web ┐
                                                                         │  one pod
 wg clients ═══════▶ OpenStack LB 83.228.201.62 ─▶ privnet-wg ──────────▶┤  (Go binary)
 resolvers  ───────▶ OpenStack LB 179.237.118.172:53 ─▶ privnet-dns ─────▶┤  DNS :5353
                                                                         │  wg0 + iptables
                                                                         └─ SQLite on PVC
```

* **One Go binary** serves the UI and owns the `wg0` kernel interface in its own pod network
  namespace (`NET_ADMIN`). After every change it reconciles WireGuard peers, the gateway
  addresses and the firewall from the database, and it re-checks them every 10 minutes.
* **Cloudflare tunnels can't carry UDP**, so WireGuard traffic enters through a separate
  `LoadBalancer` Service. On Infomaniak KaaS this is an Octavia load balancer with a public IP.
* **Hub and spoke:** every device has one peer, the hub. The hub forwards packets between
  devices of the same network.

### Address plan

| Devices | Subnet | Example | Gateway | Device slots |
|---|---|---|---|---|
| 4–5 | `/29` | `10.77.0.0/29` | `.1` | `.2`–`.6` |
| 6–13 | `/28` | `10.77.0.16/28` | `.17` | `.18`–`.30` |
| 14–16 | `/27` | `10.77.0.32/27` | `.33` | `.34`–`.49` |

Only the number of slots you choose can be assigned. Client configs use
`AllowedIPs = <network subnet>`, so only private-network traffic uses the tunnel (split tunnel).

### Isolation and security

* iptables in the pod: `FORWARD` policy is `DROP`. Only `wg0 → wg0` traffic with **source and
  destination in the same network subnet** is accepted, so networks can't see each other.
* Nothing is NATed or forwarded to the pod/cluster network. From the tunnel, clients can only
  ping their gateway address on the hub.
* Device private keys and PSKs are encrypted at rest (AES-GCM, key derived from `APP_SECRET`).
  Every peer also uses a preshared key.
* Share links are random 256-bit tokens, stored only as hashes, valid for `SHARE_TTL` and
  revocable. Session cookies are `HttpOnly`, `Secure` and `SameSite=Lax`, and requests from
  other origins are rejected. A strict CSP is set.
* Bring-your-own-key: add a device with your own public key and the private key never leaves
  the device.

## Private-IP DNS and certificates

privnet is the authoritative nameserver for `DNS_ZONE` (`ip.kizy.ch`). Every name looks like
`<host>.<namespace>.ip.kizy.ch`:

| Name | Resolves to |
|---|---|
| `192-168-1-10.home.ip.kizy.ch` | `192.168.1.10` |
| `app-192-168-1-10.home.ip.kizy.ch` | `192.168.1.10` (covered by the `*.home…` wildcard) |
| `app.192-168-1-10.home.ip.kizy.ch`, `192.168.1.10.home.ip.kizy.ch` | `192.168.1.10` |
| `nas.home.ip.kizy.ch` | custom record set in the UI |
| `anna-laptop.home-lab-x7k2.ip.kizy.ch` | privnet device IP (each network gets a namespace) |

* **Namespaces are owned.** Plain nip.io can't safely issue certificates, because anyone could get
  one for `192-168-1-10.nip.io`. Here only the namespace owner can answer DNS-01 challenges for
  `*.home.ip.kizy.ch`, so a wildcard cert covers every name in the namespace.
* **Only private ranges** (10/8, 172.16/12, 192.168/16, 100.64/10, 127/8) are answered. No recursion,
  ANY is minimised (RFC 8482), CAA at the apex allows only Let's Encrypt.
* Names inside an existing namespace return NODATA instead of NXDOMAIN, so resolvers implementing
  RFC 8020 (such as Let's Encrypt's Unbound) never hide `_acme-challenge` names.
* **ACME API:** `POST /acme-dns/update` is compatible with acme-dns
  (`X-Api-User`, `X-Api-Key`, `{"subdomain": "<namespace>", "txt": "…"}`), so lego, Traefik,
  cert-manager, acme.sh and Caddy work unchanged. The UI has a recipe per client with the
  namespace's real values. The 5 newest challenge values are kept for 24 h.

### Delegation (one-time, in Cloudflare)

| Type | Name | Content | Proxy |
|---|---|---|---|
| A | `privnet-ns.kizy.ch` | `179.237.118.172` (Service `privnet-dns`) | DNS only |
| NS | `ip.kizy.ch` | `privnet-ns.kizy.ch` | – |

Let's Encrypt limits are per registered domain (`kizy.ch`), and all namespaces share them.
For heavy use, run the zone on a dedicated domain and add it to the Public Suffix List.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `APP_SECRET` | – (required) | Encryption key for stored WireGuard keys. **Don't change it after first use.** |
| `WG_ENDPOINT` | – (required) | Public `host:port` written into client configs |
| `BASE_URL` | `http://localhost:8080` | Public URL of the UI (used for share links and cookie `Secure`) |
| `WG_POOL` | `10.77.0.0/16` | Pool that network subnets are carved from |
| `WG_PORT` / `WG_MTU` / `WG_KEEPALIVE` | `51820` / `1380` / `25` | Hub port, tunnel MTU, client keepalive |
| `SIGNUP_MODE` | `open` | `open`, `code` (requires `SIGNUP_CODE`) or `closed` |
| `MAX_NETWORKS_PER_USER` | `3` | Limit per account |
| `SHARE_TTL` | `72h` | Lifetime of onboarding links |
| `DB_PATH` | `privnet.db` | SQLite file |
| `WG_MODE` | `kernel` | `fake` for UI development without WireGuard (e.g. macOS) |
| `DNS_ZONE` | – | Zone served by the DNS service, e.g. `ip.kizy.ch` (empty = disabled) |
| `DNS_NAMESERVER` / `DNS_PUBLIC_IP` | – | NS hostname delegated to, and its public IP |
| `DNS_LISTEN` | `:5353` | DNS listen address (UDP+TCP) |
| `MAX_DNS_ZONES_PER_USER` / `MAX_DNS_RECORDS_PER_ZONE` | `3` / `64` | Limits |

The MTU is 1380 because the pod's eth0 has MTU 1450 (Cilium overlay) and WireGuard adds up to 80 bytes.

## Development

```bash
go test ./...
APP_SECRET=devsecretdevsecret WG_ENDPOINT=203.0.113.1:51820 WG_MODE=fake go run ./cmd/privnet
# open http://localhost:8080
```

## Deploy (xuno cluster)

```bash
deploy/deploy.sh
```

The script builds a `linux/amd64` image tagged with the git SHA, pushes it to Docker Hub (`docker.io/dameyerdave/privnet`), creates
`APP_SECRET` once (and reuses the one in the cluster after that), waits for the load balancer IP,
writes it into `WG_ENDPOINT`, and applies `deploy/k8s` with kustomize.

Cluster requirements: kernel WireGuard on the nodes (Linux ≥ 5.6), and permission to run a
privileged init container that sets `net.ipv4.ip_forward=1` in the pod's own network namespace.

### Operations

```bash
kubectl -n privnet logs deploy/privnet
kubectl -n privnet exec deploy/privnet -- wg show wg0
kubectl -n privnet exec deploy/privnet -- iptables -S
```

Back up the PVC `privnet-data` (SQLite) together with `APP_SECRET`.
