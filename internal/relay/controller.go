package relay

import (
	"sync"
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Controller persists per-peer relay state across iterations and adapts it
// based on current wgctrl state and directory contents.
//
// Each iteration the daemon calls Update with a fresh wgctrl snapshot and
// directory; the controller decides per-peer mode and returns the set of
// peer public keys that should be routed through the relay target.
//
// MarkNetChanged is intended to be called from a netlink watcher: it sets a
// one-shot flag that the next Update consumes to probe direct connectivity
// for every relayed peer.
type Controller struct {
	cfg Config

	mu             sync.Mutex
	states         map[string]PeerState // peer.PublicKey -> state
	netChangedOnce bool
}

func NewController(cfg Config) *Controller {
	return &Controller{
		cfg:    cfg.withDefaults(),
		states: make(map[string]PeerState),
	}
}

// MarkNetChanged signals that this host's local network address set may have
// changed (e.g. wifi reassociation, DHCP rebind). The next Update will treat
// every relayed peer as if its probe interval had elapsed.
func (c *Controller) MarkNetChanged() {
	c.mu.Lock()
	c.netChangedOnce = true
	c.mu.Unlock()
}

// Decision is the result of one Update call: per-peer state plus the set of
// peers that should be relayed in the next WG reconcile.
type Decision struct {
	Relayed    map[string]bool      // peer.PublicKey -> true if relayed
	PeerStates map[string]PeerState // for status display and tests
	RelayTarget *directory.Node     // chosen relay node, or nil if none available
}

// Update advances the per-peer state machine. It returns the set of peer
// public keys whose traffic should be routed via the relay target in the
// next WG configuration. Pass the current wgctrl peer snapshot and the
// directory that the daemon just synced.
//
// If `self` has its own public Endpoint (admin/public-relay role), Update
// returns an empty decision: such nodes already have direct paths to all
// peers and don't benefit from relaying.
func (c *Controller) Update(self directory.Node, dir directory.Directory, peers []wgtypes.Peer, now time.Time) Decision {
	c.mu.Lock()
	defer c.mu.Unlock()

	netChanged := c.netChangedOnce
	c.netChangedOnce = false

	if self.Endpoint != "" {
		c.states = make(map[string]PeerState)
		return Decision{}
	}

	target := pickRelayTarget(dir, self.PublicKey)

	peerByKey := indexPeers(peers)
	newStates := make(map[string]PeerState, len(dir.Nodes))
	relayed := make(map[string]bool)

	for _, node := range dir.Nodes {
		if node.PublicKey == self.PublicKey {
			continue
		}
		// Peers with an operator-configured public endpoint don't need relay.
		if node.Endpoint != "" {
			newStates[node.PublicKey] = PeerState{Mode: ModeDirect, EnteredAt: now}
			continue
		}
		// Can't relay if there's no relay target, or the peer itself IS the
		// relay target.
		if target == nil || node.PublicKey == target.PublicKey {
			newStates[node.PublicKey] = PeerState{Mode: ModeDirect, EnteredAt: now}
			continue
		}

		prev, hasPrev := c.states[node.PublicKey]
		if !hasPrev {
			prev = PeerState{Mode: ModeDirect, EnteredAt: now}
		}

		pub, err := keys.ParseWGPublic(node.PublicKey)
		if err != nil {
			// Bad data — fall back to direct so we don't strand the peer.
			newStates[node.PublicKey] = PeerState{Mode: ModeDirect, EnteredAt: now}
			continue
		}

		next := Decide(Inputs{
			Now:             now,
			Previous:        prev,
			Peer:            peerByKey[pub],
			Node:            node,
			LocalNetChanged: netChanged,
		}, c.cfg)
		newStates[node.PublicKey] = next
		if next.Mode == ModeRelayed {
			relayed[node.PublicKey] = true
		}
	}

	c.states = newStates
	return Decision{
		Relayed:     relayed,
		PeerStates:  newStates,
		RelayTarget: target,
	}
}

// pickRelayTarget returns the first node in the directory (excluding self)
// with a non-empty Endpoint. Multi-relay topologies aren't supported yet.
func pickRelayTarget(dir directory.Directory, selfPub string) *directory.Node {
	for i := range dir.Nodes {
		if dir.Nodes[i].PublicKey == selfPub {
			continue
		}
		if dir.Nodes[i].Endpoint != "" {
			return &dir.Nodes[i]
		}
	}
	return nil
}

func indexPeers(peers []wgtypes.Peer) map[wgtypes.Key]wgtypes.Peer {
	m := make(map[wgtypes.Key]wgtypes.Peer, len(peers))
	for _, p := range peers {
		m[p.PublicKey] = p
	}
	return m
}
