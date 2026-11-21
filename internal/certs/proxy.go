package certs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Route maps one HTTPS name on the hub to a device inside a private network.
type Route struct {
	Host       string // lower-case FQDN, e.g. nas.home-ab12.ip.kizy.ch
	Cert       *tls.Certificate
	Subnet     netip.Prefix // only clients of this network may use the route
	Gateway    netip.Addr   // the hub's address in that network (listen + source address)
	Backend    netip.AddrPort
	BackendTLS bool // speak HTTPS to the device without verifying its certificate
	proxy      *httputil.ReverseProxy
}

// Proxy terminates TLS for Routes and forwards plain HTTP (or HTTPS) to the
// device over the WireGuard tunnel. A client can only reach routes of its own
// network: the TLS handshake and every request check that the client address
// lies in the route's subnet and that it connected to that network's gateway.
type Proxy struct {
	routes atomic.Pointer[map[string]*Route]
}

func NewProxy() *Proxy {
	p := &Proxy{}
	m := map[string]*Route{}
	p.routes.Store(&m)
	return p
}

// Update atomically replaces the route table.
func (p *Proxy) Update(routes []*Route) {
	m := make(map[string]*Route, len(routes))
	for _, r := range routes {
		r.Host = strings.ToLower(r.Host)
		r.proxy = newReverseProxy(r)
		m[r.Host] = r
	}
	p.routes.Store(&m)
}

func (p *Proxy) route(host string) *Route {
	return (*p.routes.Load())[strings.ToLower(strings.TrimSuffix(host, "."))]
}

func newReverseProxy(r *Route) *httputil.ReverseProxy {
	scheme := "http"
	if r.BackendTLS {
		scheme = "https"
	}
	target := &url.URL{Scheme: scheme, Host: r.Backend.String()}
	// Dial from the network's own gateway address. Otherwise the kernel may
	// pick another network's gateway as source and the device's reply would
	// never make it back into the tunnel.
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second,
		LocalAddr: &net.TCPAddr{IP: r.Gateway.AsSlice()}}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // devices often use self-signed certs
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // keep the public name for virtual hosts and redirects
			pr.SetXForwarded()
		},
		Transport: tr,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			slog.Warn("proxy backend", "host", r.Host, "backend", r.Backend, "err", err)
			http.Error(w, fmt.Sprintf("privnet proxy: %s is not answering on %s port %d.\nIs the device connected and the service running?",
				r.Host, scheme, r.Backend.Port()), http.StatusBadGateway)
		},
	}
}

func addrOf(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		ip, _ := netip.AddrFromSlice(ta.IP)
		return ip.Unmap()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// allowed reports whether a connection from remote to local may use r.
func (r *Route) allowed(remote, local netip.Addr) bool {
	return r.Subnet.Contains(remote) && local == r.Gateway
}

func (p *Proxy) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r := p.route(hello.ServerName)
	if r == nil {
		return nil, errors.New("unknown server name")
	}
	if !r.allowed(addrOf(hello.Conn.RemoteAddr()), addrOf(hello.Conn.LocalAddr())) {
		return nil, errors.New("name not available to this client")
	}
	return r.Cert, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.TLS == nil {
		http.Error(w, "https only", http.StatusBadRequest)
		return
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// The Host header must match the TLS name so one network can't reach
	// another network's route through a shared connection.
	if !strings.EqualFold(host, req.TLS.ServerName) {
		http.Error(w, "host does not match TLS server name", http.StatusMisdirectedRequest)
		return
	}
	r := p.route(host)
	remote, _ := netip.ParseAddrPort(req.RemoteAddr)
	local, _ := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if r == nil || local == nil || !r.allowed(remote.Addr().Unmap(), addrOf(local)) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	r.proxy.ServeHTTP(w, req)
}

// redirect sends plain-HTTP requests for known names to HTTPS.
func (p *Proxy) redirect(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	r := p.route(host)
	remote, _ := netip.ParseAddrPort(req.RemoteAddr)
	local, _ := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if r == nil || local == nil || !r.allowed(remote.Addr().Unmap(), addrOf(local)) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.Redirect(w, req, "https://"+r.Host+req.URL.RequestURI(), http.StatusPermanentRedirect)
}

// Serve listens for HTTPS on httpsAddr and (optionally) redirects HTTP on
// httpAddr until ctx is cancelled.
func (p *Proxy) Serve(ctx context.Context, httpsAddr, httpAddr string) error {
	hs := &http.Server{
		Addr:              httpsAddr,
		Handler:           p,
		TLSConfig:         &tls.Config{GetCertificate: p.getCertificate, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0), // handshake noise from scanners
	}
	servers := []*http.Server{hs}
	errc := make(chan error, 2)
	go func() { errc <- hs.ListenAndServeTLS("", "") }()
	if httpAddr != "" {
		h := &http.Server{Addr: httpAddr, Handler: http.HandlerFunc(p.redirect), ReadHeaderTimeout: 15 * time.Second}
		servers = append(servers, h)
		go func() { errc <- h.ListenAndServe() }()
	}
	slog.Info("https proxy listening", "https", httpsAddr, "http", httpAddr)
	shutdown := func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, s := range servers {
			_ = s.Shutdown(sctx)
		}
	}
	select {
	case <-ctx.Done():
		shutdown()
		return nil
	case err := <-errc:
		shutdown()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
