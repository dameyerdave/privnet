package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, host string) *tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestProxyIsolation(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from device host="+r.Host+" xfp="+r.Header.Get("X-Forwarded-Proto"))
	}))
	defer backend.Close()
	bAddr := netip.MustParseAddrPort(strings.TrimPrefix(backend.URL, "http://"))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	p := NewProxy()
	lo := netip.MustParseAddr("127.0.0.1")
	p.Update([]*Route{
		{Host: "ok.ns.ip.test", Cert: selfSigned(t, "ok.ns.ip.test"), Subnet: netip.MustParsePrefix("127.0.0.0/8"), Gateway: lo, Backend: bAddr},
		{Host: "other.ns.ip.test", Cert: selfSigned(t, "other.ns.ip.test"), Subnet: netip.MustParsePrefix("10.77.0.0/29"), Gateway: netip.MustParseAddr("10.77.0.1"), Backend: bAddr},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx, addr, "")
	time.Sleep(200 * time.Millisecond)

	client := func(sni string) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: sni},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			},
		}}
	}

	// Allowed: client in the subnet, connected to the gateway.
	res, err := client("ok.ns.ip.test").Get("https://ok.ns.ip.test/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "host=ok.ns.ip.test") || !strings.Contains(string(body), "xfp=https") {
		t.Fatalf("allowed route: %d %q", res.StatusCode, body)
	}

	// Another network's route: the handshake must fail.
	if _, err := client("other.ns.ip.test").Get("https://other.ns.ip.test/"); err == nil {
		t.Fatal("route of another network was reachable")
	}

	// Unknown name: handshake fails.
	if _, err := client("nope.ns.ip.test").Get("https://nope.ns.ip.test/"); err == nil {
		t.Fatal("unknown name was served")
	}

	// Host header that differs from the TLS name is rejected.
	req, _ := http.NewRequest("GET", "https://ok.ns.ip.test/", nil)
	req.Host = "other.ns.ip.test"
	res, err = client("ok.ns.ip.test").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("host mismatch: got %d", res.StatusCode)
	}
}
