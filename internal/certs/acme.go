// Package certs issues Let's Encrypt certificates for names in the privnet DNS
// zone and serves them from a TLS-terminating reverse proxy on the hub.
//
// Issuance uses ACME DNS-01. privnet is the authoritative server for the
// zone, so it publishes the challenge values itself (in memory, for the few
// seconds an order takes); no external DNS API is involved.
package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// ChallengePublisher publishes DNS-01 TXT values for a namespace label.
type ChallengePublisher interface {
	AddChallenge(label, value string)
	RemoveChallenge(label, value string)
}

// Issuer obtains certificates from an ACME CA. It is safe for concurrent use,
// but orders are serialised so the account never runs parallel orders.
type Issuer struct {
	Directory string // ACME directory URL
	Email     string // optional account contact
	DNS       ChallengePublisher
	// AccountKey loads or creates the persistent ACME account key.
	AccountKey func(ctx context.Context) (crypto.Signer, error)

	mu     sync.Mutex
	client *acme.Client
}

// Result is a freshly issued certificate.
type Result struct {
	KeyPEM   string
	CertPEM  string // leaf followed by intermediates
	NotAfter time.Time
}

func (i *Issuer) acmeClient(ctx context.Context) (*acme.Client, error) {
	if i.client != nil {
		return i.client, nil
	}
	key, err := i.AccountKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	c := &acme.Client{Key: key, DirectoryURL: i.Directory, UserAgent: "privnet"}
	acct := &acme.Account{}
	if i.Email != "" {
		acct.Contact = []string{"mailto:" + i.Email}
	}
	if _, err := c.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register ACME account: %w", err)
	}
	i.client = c
	return c, nil
}

// Issue obtains a certificate for fqdn. label is the namespace whose
// _acme-challenge name the CA will query.
func (i *Issuer) Issue(ctx context.Context, fqdn, label string) (*Result, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()

	c, err := i.acmeClient(ctx)
	if err != nil {
		return nil, err
	}
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(fqdn))
	if err != nil {
		return nil, fmt.Errorf("new order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := c.GetAuthorization(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, ch := range z.Challenges {
			if ch.Type == "dns-01" {
				chal = ch
				break
			}
		}
		if chal == nil {
			return nil, errors.New("CA offered no dns-01 challenge")
		}
		val, err := c.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, err
		}
		i.DNS.AddChallenge(label, val)
		_, err = c.Accept(ctx, chal)
		if err == nil {
			_, err = c.WaitAuthorization(ctx, z.URI)
		}
		i.DNS.RemoveChallenge(label, val)
		if err != nil {
			return nil, fmt.Errorf("dns-01 validation: %w", cleanErr(err))
		}
	}
	if order, err = c.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("order: %w", cleanErr(err))
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: fqdn}, DNSNames: []string{fqdn},
	}, key)
	if err != nil {
		return nil, err
	}
	der, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("finalize: %w", cleanErr(err))
	}
	if len(der) == 0 {
		return nil, errors.New("CA returned no certificate")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, err
	}
	var chain strings.Builder
	for _, b := range der {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: b})
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	slog.Info("certificate issued", "name", fqdn, "not_after", leaf.NotAfter)
	return &Result{
		KeyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})),
		CertPEM:  chain.String(),
		NotAfter: leaf.NotAfter,
	}, nil
}

// cleanErr unwraps ACME problem details into a readable message.
func cleanErr(err error) error {
	var oe *acme.OrderError
	if errors.As(err, &oe) {
		return fmt.Errorf("order %s", oe.Status)
	}
	var ae *acme.AuthorizationError
	if errors.As(err, &ae) {
		msgs := make([]string, 0, len(ae.Errors))
		for _, e := range ae.Errors {
			msgs = append(msgs, e.Error())
		}
		if len(msgs) > 0 {
			return errors.New(strings.Join(msgs, "; "))
		}
	}
	return err
}

// NewAccountKey creates a key suitable for an ACME account.
func NewAccountKey() (crypto.Signer, string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, "", err
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})), nil
}

// ParseAccountKey parses a key created by NewAccountKey.
func ParseAccountKey(p string) (crypto.Signer, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, errors.New("invalid account key PEM")
	}
	return x509.ParseECPrivateKey(b.Bytes)
}
