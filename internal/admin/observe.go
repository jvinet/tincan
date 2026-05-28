package admin

import (
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	DefaultHandshakeFresh  = 3 * time.Minute
	DefaultRefreshInterval = 15 * time.Minute
)

// MergeObservations updates each directory node's ObservedEndpoint/ObservedAt
// based on what the admin's WireGuard interface currently sees about each
// peer's source endpoint. It returns the (possibly updated) directory plus a
// flag the caller should use to decide whether to bump+republish.
//
// Per-node rules:
//   - Nodes with an operator-configured Endpoint are left untouched (operator
//     intent wins over discovery).
//   - If wgctrl has a recent handshake from the peer (within handshakeFresh)
//     and we've never observed it before, or the observed endpoint string
//     differs from the published one, or the published ObservedAt is older
//     than refreshInterval, the observation is recorded.
//   - If wgctrl has no recent handshake but a prior observation exists in the
//     directory, it is cleared so clients stop trying a stale endpoint.
func MergeObservations(dir directory.Directory, peers []wgtypes.Peer, now time.Time, handshakeFresh, refreshInterval time.Duration) (directory.Directory, bool) {
	if handshakeFresh <= 0 {
		handshakeFresh = DefaultHandshakeFresh
	}
	if refreshInterval <= 0 {
		refreshInterval = DefaultRefreshInterval
	}

	byKey := make(map[wgtypes.Key]wgtypes.Peer, len(peers))
	for _, peer := range peers {
		byKey[peer.PublicKey] = peer
	}

	out := dir
	out.Nodes = append([]directory.Node(nil), dir.Nodes...)
	changed := false
	nowUTC := now.UTC()

	for i := range out.Nodes {
		n := &out.Nodes[i]
		if n.Endpoint != "" {
			continue
		}
		pub, err := keys.ParseWGPublic(n.PublicKey)
		if err != nil {
			continue
		}
		peer, ok := byKey[pub]

		hasFreshHandshake := ok && peer.Endpoint != nil &&
			!peer.LastHandshakeTime.IsZero() &&
			now.Sub(peer.LastHandshakeTime) <= handshakeFresh

		if hasFreshHandshake {
			observed := peer.Endpoint.String()
			endpointChanged := n.ObservedEndpoint != observed
			firstObservation := n.ObservedAt.IsZero()
			needsRefresh := !firstObservation && now.Sub(n.ObservedAt) >= refreshInterval
			if endpointChanged || firstObservation || needsRefresh {
				n.ObservedEndpoint = observed
				n.ObservedAt = nowUTC
				changed = true
			}
		} else {
			if n.ObservedEndpoint != "" || !n.ObservedAt.IsZero() {
				n.ObservedEndpoint = ""
				n.ObservedAt = time.Time{}
				changed = true
			}
		}
	}
	return out, changed
}
