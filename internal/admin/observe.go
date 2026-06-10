package admin

import (
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const DefaultHandshakeFresh = 3 * time.Minute

// MergeObservations updates each directory node's ObservedEndpoint/ObservedAt
// based on what the admin's WireGuard interface currently sees about each
// peer's source endpoint. It returns the (possibly updated) directory plus a
// flag the caller should use to decide whether to bump+republish.
//
// Per-node rules:
//   - Nodes with an operator-configured Endpoint are left untouched (operator
//     intent wins over discovery).
//   - If wgctrl has a recent handshake from the peer (within handshakeFresh)
//     and the observed source endpoint differs from what's published (which
//     includes the first-ever observation), the new endpoint is recorded.
//   - A handshake only vouches for the kernel's current endpoint if it
//     happened *after* the daemon last pushed an endpoint into the kernel for
//     that peer (pushedAt, keyed by base64 pubkey; see wg.Manager.Apply).
//     The kernel cannot distinguish a wire-derived endpoint from one we just
//     configured, so without this check a recent-but-older handshake would
//     let a config-pushed endpoint — e.g. a spoofed LAN-discovery beacon's
//     address — be laundered into the signed directory as "observed". Such
//     a peer is left untouched until a fresh handshake validates the push.
//   - If wgctrl has a recent handshake but the observed endpoint is unchanged,
//     the node is left untouched — we deliberately do NOT re-stamp ObservedAt.
//     Clients trust a published observed endpoint for as long as it stays in
//     the directory (there is no client-side TTL), so re-stamping would only
//     churn the serial and force a needless republish.
//   - If wgctrl has no recent handshake but a prior observation exists in the
//     directory, it is cleared so clients stop trying a stale endpoint.
func MergeObservations(dir directory.Directory, peers []wgtypes.Peer, now time.Time, handshakeFresh time.Duration, pushedAt map[string]time.Time) (directory.Directory, bool) {
	if handshakeFresh <= 0 {
		handshakeFresh = DefaultHandshakeFresh
	}

	byKey := make(map[wgtypes.Key]wgtypes.Peer, len(peers))
	for _, peer := range peers {
		byKey[peer.PublicKey] = peer
	}

	out := dir
	out.Nodes = append([]directory.Node(nil), dir.Nodes...)
	changed := false
	// Second precision to match directory.Stamp(); see its doc for why.
	nowUTC := now.UTC().Truncate(time.Second)

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
			// Zero pushedAt (never pushed, or pushed before this handshake)
			// means the endpoint is wire-derived and safe to publish.
			if !peer.LastHandshakeTime.After(pushedAt[n.PublicKey]) {
				continue
			}
			observed := peer.Endpoint.String()
			// Only record a genuinely new endpoint (this also covers the first
			// observation, where ObservedEndpoint is still empty). An unchanged
			// endpoint is left as-is: re-stamping ObservedAt would bump the
			// serial and republish without changing any routing.
			if n.ObservedEndpoint != observed {
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
