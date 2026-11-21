package web

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// limiter is a sliding-window failure counter: after max events within window
// a key is blocked until the oldest event ages out. It lives in memory, which
// is fine for a single-replica service; a restart simply clears it.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	now    func() time.Time
	hits   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, now: time.Now, hits: map[string][]time.Time{}}
}

// prune drops expired events of key; callers hold mu.
func (l *limiter) prune(key string, now time.Time) []time.Time {
	h := l.hits[key]
	i := 0
	for i < len(h) && now.Sub(h[i]) >= l.window {
		i++
	}
	h = h[i:]
	if len(h) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = h
	}
	return h
}

// blocked reports whether key is over the limit and how long until it may try again.
func (l *limiter) blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	h := l.prune(key, now)
	if len(h) < l.max {
		return false, 0
	}
	return true, h[0].Add(l.window).Sub(now)
}

// add records one event for key.
func (l *limiter) add(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.hits[key] = append(l.prune(key, now), now)
	if len(l.hits) > 50000 { // bound memory under a flood of distinct keys
		for k := range l.hits {
			l.prune(k, now)
		}
	}
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}

// limits groups the limiters used by the web server.
type limits struct {
	loginAccount *limiter // failed logins per account
	loginIP      *limiter // failed logins per client
	signupIP     *limiter // sign-up attempts per client
	tokenIP      *limiter // invalid tokens (share links, cert fetch, acme-dns) per client
}

func newLimits() *limits {
	return &limits{
		loginAccount: newLimiter(10, 15*time.Minute),
		loginIP:      newLimiter(30, 15*time.Minute),
		signupIP:     newLimiter(10, time.Hour),
		tokenIP:      newLimiter(30, 15*time.Minute),
	}
}

// clientIP identifies the client. Traffic reaches privnet only through the
// Cloudflare tunnel, which sets CF-Connecting-IP; otherwise the peer address is used.
func clientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
		if a, err := netip.ParseAddr(v); err == nil {
			return a.String()
		}
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// waitText renders a retry delay for people: "1 minute", "12 minutes".
func waitText(d time.Duration) string {
	m := int(d.Round(time.Minute).Minutes())
	if m <= 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

// tooManyTokens rejects clients that guessed too many invalid tokens. It
// returns true when the request was answered.
func (s *Server) tooManyTokens(w http.ResponseWriter, r *http.Request) bool {
	if ok, wait := s.limits.tokenIP.blocked(clientIP(r)); ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		http.Error(w, "too many invalid requests, try again in "+waitText(wait), http.StatusTooManyRequests)
		return true
	}
	return false
}

func (s *Server) badToken(r *http.Request) { s.limits.tokenIP.add(clientIP(r)) }
