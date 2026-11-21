package web

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(3, time.Minute)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if ok, _ := l.blocked("a"); ok {
			t.Fatalf("blocked after %d events", i)
		}
		l.add("a")
	}
	ok, wait := l.blocked("a")
	if !ok || wait != time.Minute {
		t.Fatalf("want blocked for 1m, got %v %v", ok, wait)
	}
	if ok, _ := l.blocked("b"); ok {
		t.Fatal("other key blocked")
	}
	now = now.Add(61 * time.Second)
	if ok, _ := l.blocked("a"); ok {
		t.Fatal("still blocked after the window")
	}
	l.add("a")
	l.reset("a")
	if len(l.hits) != 0 {
		t.Fatal("reset left events behind")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	if got := clientIP(r); got != "10.0.0.5" {
		t.Fatalf("remote: %s", got)
	}
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("cf: %s", got)
	}
	r.Header.Set("CF-Connecting-IP", "not-an-ip")
	if got := clientIP(r); got != "10.0.0.5" {
		t.Fatalf("invalid cf header must be ignored: %s", got)
	}
}

func TestPasswordProblem(t *testing.T) {
	for pw, bad := range map[string]bool{"short": true, "long enough pw": false, string(make([]byte, 73)): true, string(make([]byte, 72)): false} {
		if got := passwordProblem(pw) != ""; got != bad {
			t.Errorf("len %d: problem=%v want %v", len(pw), got, bad)
		}
	}
}
