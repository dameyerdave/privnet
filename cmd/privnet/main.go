// Command privnet runs the WireGuard hub and its web UI.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/dameyerdave/privnet/internal/cookbook"
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
	}, st, mgr, webassets.FS)
	if err != nil {
		return err
	}
	if err := srv.Sync(ctx); err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}
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
