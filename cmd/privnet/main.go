// Command privnet runs the WireGuard hub and its web UI.
package main

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/dameyerdave/privnet/internal/certs"
	"github.com/dameyerdave/privnet/internal/cookbook"
	pdns "github.com/dameyerdave/privnet/internal/dns"
	"github.com/dameyerdave/privnet/internal/store"
	"github.com/dameyerdave/privnet/internal/web"
	"github.com/dameyerdave/privnet/internal/wg"
	webassets "github.com/dameyerdave/privnet/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envAllowEmpty is like env, but an explicitly empty value (KEY=) means "off".
func envAllowEmpty(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	secret := os.Getenv("APP_SECRET")
	if len(secret) < 16 {
		return errors.New("APP_SECRET must be set (at least 16 characters)")
	}
	pool, err := netip.ParsePrefix(env("WG_POOL", "10.77.0.0/16"))
	if err != nil {
		return fmt.Errorf("WG_POOL: %w", err)
	}
	endpoint := os.Getenv("WG_ENDPOINT")
	if endpoint == "" {
		return errors.New("WG_ENDPOINT must be set to the public host:port clients connect to")
	}
	port := envInt("WG_PORT", 51820)
	mtu := envInt("WG_MTU", 1380)
	shareTTL, err := time.ParseDuration(env("SHARE_TTL", "72h"))
	if err != nil {
		return fmt.Errorf("SHARE_TTL: %w", err)
	}

	st, err := store.Open(env("DB_PATH", "privnet.db"), secret)
	if err != nil {
		return err
	}
	defer st.Close()

	priv, err := serverKey(ctx, st)
	if err != nil {
		return err
	}

	var mgr wg.Manager
	switch env("WG_MODE", "kernel") {
	case "fake":
		mgr = &wg.Fake{}
	default:
		k, err := wg.NewKernel(env("WG_IFACE", "wg0"), port, mtu, pool, priv)
		if err != nil {
			return fmt.Errorf("wireguard: %w", err)
		}
		mgr = k
	}

	// Optional private-IP DNS service with ACME DNS-01 support.
	dnsCfg := web.DNSConfig{
		Zone:              strings.TrimSuffix(strings.ToLower(os.Getenv("DNS_ZONE")), "."),
		Nameserver:        env("DNS_NAMESERVER", "ns."+os.Getenv("DNS_ZONE")),
		PublicIP:          os.Getenv("DNS_PUBLIC_IP"),
		MaxZonesPerUser:   envInt("MAX_DNS_ZONES_PER_USER", 3),
		MaxRecordsPerZone: envInt("MAX_DNS_RECORDS_PER_ZONE", 64),
	}
	var dnsSrv *pdns.Server
	if dnsCfg.Enabled() {
		c := pdns.Config{Zone: dnsCfg.Zone, Nameservers: []string{dnsCfg.Nameserver}, Hostmaster: "hostmaster." + dnsCfg.Zone, CAAIssuer: env("DNS_CAA_ISSUER", "letsencrypt.org")}
		if a, err := netip.ParseAddr(dnsCfg.PublicIP); err == nil {
			c.NSAddr = a
		}
		dnsSrv = pdns.New(c)
	}

	srv, err := web.New(web.Config{
		BaseURL: env("BASE_URL", "http://localhost:8080"),
		Pool:    pool,
		Settings: cookbook.Settings{
			Endpoint: endpoint, ServerPublicKey: priv.PublicKey().String(), MTU: mtu, Keepalive: envInt("WG_KEEPALIVE", 25),
		},
		SignupMode:         env("SIGNUP_MODE", "open"),
		SignupCode:         os.Getenv("SIGNUP_CODE"),
		MaxNetworksPerUser: envInt("MAX_NETWORKS_PER_USER", 3),
		ShareTTL:           shareTTL,
		DNS:                dnsCfg,
	}, st, mgr, dnsSrv, webassets.FS)
	if err != nil {
		return err
	}
	// Optional per-device HTTPS certificates (Let's Encrypt via DNS-01 on our
	// own zone) and the hub's TLS-terminating proxy inside the tunnels.
	var proxy *certs.Proxy
	if dnsSrv != nil && env("CERTS", "on") == "on" {
		dir := env("ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory")
		issuer := &certs.Issuer{Directory: dir, Email: os.Getenv("ACME_EMAIL"), DNS: dnsSrv,
			AccountKey: func(ctx context.Context) (crypto.Signer, error) { return acmeAccountKey(ctx, st) }}
		defProxy := ":443"
		if env("WG_MODE", "kernel") == "fake" {
			defProxy = ""
		}
		proxyAddr := envAllowEmpty("PROXY_LISTEN", defProxy)
		if proxyAddr != "" {
			proxy = certs.NewProxy()
		}
		renewBefore, err := time.ParseDuration(env("CERT_RENEW_BEFORE", "720h"))
		if err != nil {
			return fmt.Errorf("CERT_RENEW_BEFORE: %w", err)
		}
		srv.EnableCerts(web.CertsConfig{
			Enabled: true, MaxPerUser: envInt("MAX_CERTS_PER_USER", 10), MaxPerDevice: envInt("MAX_CERTS_PER_DEVICE", 3),
			Proxy: proxy != nil, RenewBefore: renewBefore, RetryAfter: 6 * time.Hour,
			Staging: strings.Contains(dir, "staging"),
		}, issuer, proxy)
		go srv.RunCertWorker(ctx)
		if proxy != nil {
			go func() {
				if err := proxy.Serve(ctx, proxyAddr, envAllowEmpty("PROXY_HTTP_LISTEN", ":80")); err != nil {
					slog.Error("https proxy stopped", "err", err)
				}
			}()
		}
		slog.Info("https certificates enabled", "acme", dir, "proxy", proxyAddr)
	}
	if err := srv.EnsureNetworkZones(ctx); err != nil {
		return fmt.Errorf("dns backfill: %w", err)
	}
	if err := srv.Sync(ctx); err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}
	if dnsSrv != nil {
		go func() {
			if err := dnsSrv.ListenAndServe(ctx, env("DNS_LISTEN", ":5353")); err != nil {
				slog.Error("dns", "err", err)
				stop()
			}
		}()
	}
	srv.RenewCerts(ctx)
	slog.Info("wireguard hub ready", "endpoint", endpoint, "public_key", priv.PublicKey().String(), "pool", pool)

	// Periodic housekeeping: purge expired sessions/shares and re-assert kernel
	// state in case anything drifted.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.PurgeExpired(ctx); err != nil {
					slog.Warn("purge", "err", err)
				}
				if err := srv.Sync(ctx); err != nil {
					slog.Warn("resync", "err", err)
				}
				srv.RenewCerts(ctx)
			}
		}
	}()

	hs := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: srv.Routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	slog.Info("http listening", "addr", hs.Addr)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// acmeAccountKey loads the ACME account key, creating it on first use.
func acmeAccountKey(ctx context.Context, st *store.Store) (crypto.Signer, error) {
	if v, err := st.SecretSetting(ctx, "acme_account_key"); err == nil {
		return certs.ParseAccountKey(v)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	k, p, err := certs.NewAccountKey()
	if err != nil {
		return nil, err
	}
	slog.Info("generated new ACME account key")
	return k, st.SetSecretSetting(ctx, "acme_account_key", p)
}

// serverKey loads the hub's WireGuard private key, creating it on first start.
func serverKey(ctx context.Context, st *store.Store) (wgtypes.Key, error) {
	if v, err := st.SecretSetting(ctx, "server_private_key"); err == nil {
		return wgtypes.ParseKey(v)
	} else if !errors.Is(err, store.ErrNotFound) {
		return wgtypes.Key{}, err
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return k, err
	}
	slog.Info("generated new server key pair")
	return k, st.SetSecretSetting(ctx, "server_private_key", k.String())
}
