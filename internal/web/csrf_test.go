package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRF(t *testing.T) {
	s := &Server{}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := s.csrf(ok)

	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"get always allowed", "GET", map[string]string{"Sec-Fetch-Site": "cross-site"}, 204},
		// Regression: browsers with Referrer-Policy no-referrer send Origin: null on same-origin form posts.
		{"same-origin form with Origin null", "POST", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "null"}, 204},
		{"same-origin form", "POST", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://privnet.kizy.ch"}, 204},
		{"cross-site form", "POST", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, 403},
		{"same-site subdomain", "POST", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://other.kizy.ch"}, 403},
		{"legacy browser matching origin", "POST", map[string]string{"Origin": "https://privnet.kizy.ch"}, 204},
		{"legacy browser foreign origin", "POST", map[string]string{"Origin": "https://evil.example"}, 403},
		{"legacy browser null origin", "POST", map[string]string{"Origin": "null"}, 403},
		{"non-browser client", "POST", nil, 204},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "https://privnet.kizy.ch/signup", nil)
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, w.Code, c.want)
		}
	}
}
