package relay

import (
	"log/slog"
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
type Controller struct {
	cfg Config

	mu     sync.Mutex
	states map[string]PeerState // peer.PublicKey -> state
}

func NewController(cfg Config) *Controller {
	return &Controller{
		cfg:    cfg.withDefaults(),
		states: make(map[string]PeerState),
	}
}

// Decision is the result of one Update call: per-peer state plus the set of
// peers that should be relayed in the next WG reconcile.
type Decision struct {
	Relayed     map[string]bool      // peer.PublicKey -> true if relayed
	PeerStates  map[string]PeerState // for status display and tests
	RelayTarget *directory.Node      // chosen relay node, or nil if none available
}

// Update advances the per-peer state machine. It returns the set of peer
// public keys whose traffic should be routed via the relay target in the
// next WG configuration. Pass the current wgctrl peer snapshot and the
// directory that the daemon just synced.
//
// If `self` has its own public Endpoint (admin/public-relay role), tincan
// peers are never relayed: they initiate outbound to self's endpoint and keep
// the path alive themselves. Plain-WireGuard members are the exception — they
// only ever talk to their hub, so they are relayed from every node but the
// hub, public or not.
func (c *Controller) Update(self directory.Node, dir directory.Directory, peers []wgtypes.Peer, now time.Time) Decision {
	c.mu.Lock()
	defer c.mu.Unlock()

	target := pickRelayTarget(dir, self.PublicKey)
	if target == nil {
		slog.Debug("relay: no relay target available (no peer with public endpoint)")
	} else {
		slog.Debug("relay: target selected", "target", target.Name, "endpoint", target.Endpoint)
	}

	peerByKey := indexPeers(peers)
	newStates := make(map[string]PeerState, len(dir.Nodes))
	relayed := make(map[string]bool)

	for _, node := range dir.Nodes {
		if node.PublicKey == self.PublicKey {
			continue
		}
		// Peers with an operator-configured public endpoint don't need relay.
		if node.Endpoint != "" {
			slog.Debug("relay: peer ineligible (has public endpoint)", "peer", node.Name)
			newStates[node.PublicKey] = PeerState{Mode: ModeDirect, EnteredAt: now}
			continue
		}
		// A plain-WireGuard member is a hub-and-spoke spoke: its enrolled
		// config knows only its hub, so it never initiates to anyone else and
		// drops handshakes from keys it doesn't recognize. Direct is
		// structurally impossible from every node but the hub — relay by
		// construction, not by failure detection. The hub is RelayTarget from
		// the spoke's perspective; whenever it isn't self, it is necessarily
		// `target` too (the spoke is never a candidate, so excluding it
		// changes nothing, and excluding self only matters when self IS the
		// hub).
		if node.IsPlainWireGuard() {
			hub, ok := directory.RelayTarget(dir, node.PublicKey)
			if ok && hub.PublicKey != self.PublicKey {
				slog.Debug("relay: plain-WireGuard peer relayed via its hub", "peer", node.Name, "hub", hub.Name)
				newStates[node.PublicKey] = PeerState{Mode: ModeRelayed, EnteredAt: now}
				relayed[node.PublicKey] = true
			} else {
				slog.Debug("relay: plain-WireGuard peer direct (self is its hub, or no hub exists)", "peer", node.Name)
				newStates[node.PublicKey] = PeerState{Mode: ModeDirect, EnteredAt: now}
			}
			continue
		}
		// Tincan peers initiate outbound to self's public endpoint and keep
		// the path alive with keepalives, so a node with its own endpoint
		// never needs to relay traffic toward them.
		if self.Endpoint != "" {
			newStates[node.PublicKey] = PeerState{Mode: ModeDirect, EnteredAt: now}
			continue
		}
		// Can't relay if there's no relay target, or the peer itself IS the
		// relay target.
		if target == nil {
			slog.Debug("relay: peer forced direct (no relay target)", "peer", node.Name)
			newStates[node.PublicKey] = PeerState{Mode: ModeDirect, EnteredAt: now}
			continue
		}
		if node.PublicKey == target.PublicKey {
			slog.Debug("relay: peer forced direct (is relay target)", "peer", node.Name)
			newStates[node.PublicKey] = PeerState{Mode: ModeDirect, EnteredAt: now}
			continue
		}

		prev, hasPrev := c.states[node.PublicKey]
		if !hasPrev {
			prev = PeerState{Mode: ModeDirect, EnteredAt: now}
		}

		pub, err := keys.ParseWGPublic(node.PublicKey)
		if err != nil {
			slog.Warn("relay: invalid peer public key, forcing direct", "peer", node.Name, "error", err)
			newStates[node.PublicKey] = PeerState{Mode: ModeDirect, EnteredAt: now}
			continue
		}

		kernelPeer := peerByKey[pub]
		next := Decide(Inputs{
			Now:      now,
			Previous: prev,
			Peer:     kernelPeer,
			Node:     node,
		}, c.cfg)
		logDecision(node, prev, next, kernelPeer, now)
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

func logDecision(node directory.Node, prev, next PeerState, kp wgtypes.Peer, now time.Time) {
	handshakeAge := "never"
	if !kp.LastHandshakeTime.IsZero() {
		handshakeAge = now.Sub(kp.LastHandshakeTime).Round(time.Second).String()
	}
	slog.Debug("relay: per-peer decision",
		"peer", node.Name,
		"prev_mode", prev.Mode.String(),
		"next_mode", next.Mode.String(),
		"in_mode_for", now.Sub(prev.EnteredAt).Round(time.Second).String(),
		"handshake_age", handshakeAge,
		"tx_bytes", kp.TransmitBytes,
		"observed_endpoint", node.ObservedEndpoint,
	)
}

// pickRelayTarget returns the relay node for self, or nil if none exists. It
// defers to directory.RelayTarget — a node explicitly marked Relay, else the
// first non-self node with a public Endpoint — so the controller's choice
// matches the one wg.BuildPeerConfigs uses to fold AllowedIPs and the one
// `status` displays. They must agree, or routing and reporting diverge.
// Multi-relay topologies aren't supported yet.
func pickRelayTarget(dir directory.Directory, selfPub string) *directory.Node {
	if target, ok := directory.RelayTarget(dir, selfPub); ok {
		return &target
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
