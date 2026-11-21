// Package web implements the privnet HTTP UI.
package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dameyerdave/privnet/internal/cookbook"
	pdns "github.com/dameyerdave/privnet/internal/dns"
	"github.com/dameyerdave/privnet/internal/ipam"
	"github.com/dameyerdave/privnet/internal/store"
	"github.com/dameyerdave/privnet/internal/wg"
)

type Config struct {
	BaseURL            string // public URL of the UI, e.g. https://privnet.kizy.ch
	Pool               netip.Prefix
	Settings           cookbook.Settings
	SignupMode         string // open | code | closed
	SignupCode         string
	MaxNetworksPerUser int
	ShareTTL           time.Duration
	DNS                DNSConfig
}

type Server struct {
	cfg    Config
	store  *store.Store
	wg     wg.Manager
	dns    *pdns.Server // nil when the DNS service is disabled
	pages  map[string]*template.Template
	static fs.FS
	secure bool

	// mu serialises every mutation together with the WireGuard reconcile that
	// follows it, so IP allocation and kernel state never race.
	mu sync.Mutex
}

const sessionCookie = "privnet_session"

func New(cfg Config, st *store.Store, mgr wg.Manager, dnsSrv *pdns.Server, assets fs.FS) (*Server, error) {
	s := &Server{cfg: cfg, store: st, wg: mgr, dns: dnsSrv, secure: strings.HasPrefix(cfg.BaseURL, "https://")}
	if err := s.loadTemplates(assets); err != nil {
		return nil, err
	}
	static, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	s.static = static
	return s, nil
}

// Sync pushes the complete desired state from the database to WireGuard and DNS.
func (s *Server) Sync(ctx context.Context) error {
	if err := s.SyncDNS(ctx); err != nil {
		return err
	}
	nets, err := s.store.AllNetworks(ctx)
	if err != nil {
		return err
	}
	devs, err := s.store.AllDevices(ctx)
	if err != nil {
		return err
	}
	st := wg.State{}
	for _, n := range nets {
		st.Networks = append(st.Networks, wg.Network{Subnet: n.Subnet, Gateway: ipam.NewPlan(n.Subnet, n.MaxClients).Gateway})
	}
	for _, d := range devs {
		st.Peers = append(st.Peers, wg.Peer{PublicKey: d.PublicKey, PresharedKey: d.PresharedKey, IP: d.IP})
	}
	return s.wg.Apply(st)
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(s.static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("GET /signup", s.handleSignupForm)
	mux.HandleFunc("POST /signup", s.handleSignup)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)

	mux.HandleFunc("GET /networks", s.auth(s.handleNetworks))
	mux.HandleFunc("POST /networks", s.auth(s.handleCreateNetwork))
	mux.HandleFunc("GET /networks/{id}", s.auth(s.handleNetwork))
	mux.HandleFunc("POST /networks/{id}/delete", s.auth(s.handleDeleteNetwork))
	mux.HandleFunc("POST /networks/{id}/devices", s.auth(s.handleCreateDevice))
	mux.HandleFunc("GET /api/networks/{id}/status", s.auth(s.handleNetworkStatus))

	mux.HandleFunc("GET /devices/{id}", s.auth(s.handleDevice))
	mux.HandleFunc("GET /devices/{id}/config", s.auth(s.handleDeviceConfig))
	mux.HandleFunc("GET /devices/{id}/qr.png", s.auth(s.handleDeviceQR))
	mux.HandleFunc("POST /devices/{id}/delete", s.auth(s.handleDeleteDevice))
	mux.HandleFunc("POST /devices/{id}/shares", s.auth(s.handleCreateShare))
	mux.HandleFunc("POST /devices/{id}/shares/{sid}/revoke", s.auth(s.handleRevokeShare))

	if s.cfg.DNS.Enabled() {
		mux.HandleFunc("GET /dns", s.auth(s.handleDNSList))
		mux.HandleFunc("POST /dns", s.auth(s.handleCreateDNSZone))
		mux.HandleFunc("GET /dns/{id}", s.auth(s.handleDNSZone))
		mux.HandleFunc("POST /dns/{id}/records", s.auth(s.handleCreateDNSRecord))
		mux.HandleFunc("POST /dns/{id}/records/{rid}/delete", s.auth(s.handleDeleteDNSRecord))
		mux.HandleFunc("POST /dns/{id}/rotate", s.auth(s.handleRotateDNSKey))
		mux.HandleFunc("POST /dns/{id}/delete", s.auth(s.handleDeleteDNSZone))
		mux.HandleFunc("POST /acme-dns/update", s.handleACMEUpdate)
		mux.HandleFunc("POST /acme-dns/register", s.handleACMERegister)
		mux.HandleFunc("GET /acme-dns/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	}

	mux.HandleFunc("GET /join/{token}", s.handleJoin)
	mux.HandleFunc("GET /join/{token}/config", s.handleJoinConfig)
	mux.HandleFunc("GET /join/{token}/qr.png", s.handleJoinQR)

	return s.securityHeaders(s.csrf(mux))
}

// ---- middleware ----

type ctxKey int

const userKey ctxKey = 0

func currentUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(userKey).(*store.User)
	return u
}

func (s *Server) loadUser(r *http.Request) *store.User {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	u, err := s.store.UserBySession(r.Context(), c.Value)
	if err != nil {
		return nil
	}
	return u
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.loadUser(r)
		if u == nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	}
}

// csrf rejects state-changing requests from foreign origins. Session cookies
// are SameSite=Lax as a second layer.
//
// Modern browsers send Sec-Fetch-Site, which is authoritative. Only when it is
// missing (older browsers, non-browser clients) do we fall back to Origin.
// Note that browsers send "Origin: null" for privacy-sensitive contexts, so
// "null" must not be compared against the host when Sec-Fetch-Site is present.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true // non-browser client (curl, scripts); no ambient browser credentials risk
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin keeps share-link tokens from leaking to other sites while
		// still letting the browser send a real Origin on our own form posts.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

// ---- helpers ----

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	tok := randomToken()
	const ttl = 30 * 24 * time.Hour
	if err := s.store.CreateSession(r.Context(), tok, userID, ttl); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds()),
	})
	return nil
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "path", r.URL.Path, "err", err)
	s.renderStatus(w, r, http.StatusInternalServerError, "Something went wrong", "The server hit an unexpected error. Please try again.")
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.renderStatus(w, r, http.StatusNotFound, "Not found", "This page does not exist or you do not have access to it.")
}

// ownedNetwork loads a network and checks it belongs to the current user.
func (s *Server) ownedNetwork(r *http.Request, idStr string) (*store.Network, error) {
	var id int64
	if _, err := fmt.Sscan(idStr, &id); err != nil {
		return nil, store.ErrNotFound
	}
	n, err := s.store.Network(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if n.UserID != currentUser(r).ID {
		return nil, store.ErrNotFound
	}
	return n, nil
}

func (s *Server) ownedDevice(r *http.Request) (*store.Device, *store.Network, error) {
	var id int64
	if _, err := fmt.Sscan(r.PathValue("id"), &id); err != nil {
		return nil, nil, store.ErrNotFound
	}
	d, err := s.store.Device(r.Context(), id)
	if err != nil {
		return nil, nil, err
	}
	n, err := s.store.Network(r.Context(), d.NetworkID)
	if err != nil {
		return nil, nil, err
	}
	if n.UserID != currentUser(r).ID {
		return nil, nil, store.ErrNotFound
	}
	return d, n, nil
}

func (s *Server) handleLookupErr(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	s.serverError(w, r, err)
}
