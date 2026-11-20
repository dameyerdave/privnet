package web

import (
	"bytes"
	"encoding/base64"
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

var pageNames = []string{"home", "login", "signup", "networks", "network", "device", "status"}

func (s *Server) loadTemplates(assets fs.FS) error {
	funcs := template.FuncMap{
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
			"templates/layout.html", "templates/cookbooks.html", path.Join("templates", name+".html"))
		if err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return nil
}

type layoutData struct {
	User  any
	Title string
	Page  any
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
	if err := t.ExecuteTemplate(&buf, "layout", layoutData{User: user, Page: data}); err != nil {
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
