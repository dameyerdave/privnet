package wg

import (
	"log/slog"
	"sync"
	"time"
)

// Fake is an in-memory Manager for local development on machines without
// kernel WireGuard (e.g. macOS). Every second peer is reported as online.
type Fake struct {
	mu    sync.Mutex
	state State
}

func (f *Fake) Apply(st State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = st
	slog.Info("fake wireguard apply", "networks", len(st.Networks), "peers", len(st.Peers))
	return nil
}

func (f *Fake) Status() (map[string]PeerStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]PeerStatus{}
	for i, p := range f.state.Peers {
		if i%2 == 0 {
			out[p.PublicKey] = PeerStatus{Endpoint: "203.0.113.7:51820", LastHandshake: time.Now().Add(-42 * time.Second), RxBytes: 123456, TxBytes: 654321}
		} else {
			out[p.PublicKey] = PeerStatus{}
		}
	}
	return out, nil
}
