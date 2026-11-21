package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/dameyerdave/privnet/internal/cookbook"
)

var pageNames = []string{"home", "login", "signup", "networks", "network", "device", "status", "dns", "dnszone"}

// assetVersion hashes the static files so their URLs change on every deploy
// that changes them (CDNs such as Cloudflare cache /static for hours).
func assetVersion(assets fs.FS) string {
	h := sha256.New()
	_ = fs.WalkDir(assets, "static", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, err := fs.ReadFile(assets, p); err == nil {
				h.Write([]byte(p))
				h.Write(b)
			}
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func (s *Server) loadTemplates(assets fs.FS) error {
	ver := assetVersion(assets)
	funcs := template.FuncMap{
		"asset":         func(p string) string { return "/static/" + p + "?v=" + ver },
		"timeAgo":       timeAgo,
		"bytes":         humanBytes,
		"platformLabel": cookbook.PlatformLabel,
		"add":           func(a, b int) int { return a + b },
		"lower":         strings.ToLower,
		"date":          func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
		"until":         func(t time.Time) string { return humanDuration(time.Until(t).Round(time.Minute)) },
		"qrDataURI":     func(s string) template.URL { return template.URL(qrDataURI(s)) },
		"safeURL":       func(s string) template.URL { return template.URL(s) },
		"year":          func() int { return time.Now().Year() },
	}
	s.pages = map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := template.New(name).Funcs(funcs).ParseFS(assets,
			"templates/layout.html", "templates/cookbooks.html", "templates/acme.html", path.Join("templates", name+".html"))
		if err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return nil
}

type layoutData struct {
	DNS     bool
	User    any
	Title   string
	Page    any
	Section string // networks | dns | "" — highlights the current nav item
	Flash   string // confirmation after a redirect (?done=…)
}

// flashMessages are the confirmations a redirect can request with ?done=<key>.
// Only known keys are shown, so the URL can't inject text.
var flashMessages = map[string]string{
	"net-created":    "Network created. Add your first device to get its setup guide and QR code.",
	"net-deleted":    "Network deleted. All its devices were disconnected.",
	"device-removed": "Device removed. Its key no longer works on the hub.",
	"share-revoked":  "Share link revoked.",
	"cert-removed":   "HTTPS name removed.",
	"token-rotated":  "New download token created. Update the URLs on the device.",
	"zone-created":   "Namespace created. Its names resolve right away.",
	"zone-deleted":   "Namespace deleted.",
	"record-added":   "Name added. It resolves within a few seconds.",
	"record-removed": "Name removed.",
}

// redirectDone redirects to target and asks the next page to confirm an action.
func redirectDone(w http.ResponseWriter, r *http.Request, target, key string) {
	frag := ""
	if i := strings.IndexByte(target, '#'); i >= 0 {
		target, frag = target[:i], target[i:]
	}
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	http.Redirect(w, r, target+sep+"done="+key+frag, http.StatusSeeOther)
}

func sectionOf(path string) string {
	switch {
	case strings.HasPrefix(path, "/networks"), strings.HasPrefix(path, "/devices"):
		return "networks"
	case strings.HasPrefix(path, "/dns"):
		return "dns"
	}
	return ""
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	t := s.pages[name]
	var buf bytes.Buffer
	var user any
	if u := currentUser(r); u != nil {
		user = u
	} else if u := s.loadUser(r); u != nil {
		user = u
	}
	if err := t.ExecuteTemplate(&buf, "layout", layoutData{DNS: s.cfg.DNS.Enabled(), User: user, Page: data,
		Section: sectionOf(r.URL.Path), Flash: flashMessages[r.URL.Query().Get("done")]}); err != nil {
		slog.Error("render", "page", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, code int, title, msg string) {
	w.WriteHeader(code)
	s.render(w, r, "status", map[string]any{"Code": code, "Title": title, "Message": msg})
}

func qrDataURI(s string) string {
	png, err := qrcode.Encode(s, qrcode.Medium, 320)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

func timeAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func humanDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "now"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
