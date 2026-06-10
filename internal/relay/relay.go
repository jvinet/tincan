// Package relay decides whether traffic to a NAT'd peer should flow direct
// (peer-to-peer over WireGuard) or be tunneled through an admin/relay node.
//
// The decision is per-(self, peer) and lives entirely on the client. Admin
// nodes can't observe peer-to-peer reachability — only handshakes against
// themselves — so each client watches its own wgctrl state, detects when
// the direct path is broken, and reshuffles AllowedIPs to route the peer's
// tunnel traffic through the relay node instead.
//
// When a peer is RELAYED, it remains configured as a "shadow peer" with
// empty AllowedIPs but a live endpoint and keepalive. The kernel keeps
// attempting background handshakes on that peer; the moment one succeeds,
// LastHandshakeTime becomes fresh and Decide flips the peer back to
// DIRECT. No timed probes, no service interruption — the data path
// through the relay stays up until direct is proven viable.
//
// Plain-WireGuard members bypass the state machine entirely: a spoke's
// enrolled config knows only its hub, so direct is structurally impossible
// from any other node — including nodes with their own public endpoint —
// and the Controller relays them by construction.
package relay

import (
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Mode int

const (
	ModeDirect Mode = iota
	ModeRelayed
)

func (m Mode) String() string {
	switch m {
	case ModeDirect:
		return "direct"
	case ModeRelayed:
		return "relayed"
	default:
		return "unknown"
	}
}

const (
	// DefaultDirectFailedAfter is how long a peer can go without a fresh
	// handshake before we declare the direct path broken (in DIRECT mode) or
	// consider it viable again (in RELAYED mode, looking at shadow-peer
	// handshakes).
	DefaultDirectFailedAfter = 90 * time.Second

	// DefaultDirectGracePeriod gives the kernel time to complete a handshake
	// after entering DIRECT before we evaluate liveness. Without this, a
	// freshly added peer (LastHandshakeTime=0) would be misjudged as broken.
	DefaultDirectGracePeriod = 30 * time.Second
)

type Config struct {
	DirectFailedAfter time.Duration
	DirectGracePeriod time.Duration
}

func (c Config) withDefaults() Config {
	if c.DirectFailedAfter <= 0 {
		c.DirectFailedAfter = DefaultDirectFailedAfter
	}
	if c.DirectGracePeriod <= 0 {
		c.DirectGracePeriod = DefaultDirectGracePeriod
	}
	return c
}

// PeerState is what Decide reads and writes between iterations. The caller
// (relay.Controller) owns the storage.
type PeerState struct {
	Mode      Mode
	EnteredAt time.Time
}

// Inputs are the per-peer signals Decide needs to make a transition.
type Inputs struct {
	Now      time.Time
	Previous PeerState
	Peer     wgtypes.Peer
	Node     directory.Node
}

// Decide returns the next PeerState given the previous one and the current
// observable inputs. It does not perform I/O.
func Decide(in Inputs, cfg Config) PeerState {
	cfg = cfg.withDefaults()
	out := in.Previous

	handshakeFresh := !in.Peer.LastHandshakeTime.IsZero() &&
		in.Now.Sub(in.Peer.LastHandshakeTime) < cfg.DirectFailedAfter

	switch in.Previous.Mode {
	case ModeDirect:
		// Grace period: give the kernel time to handshake before judging.
		if in.Now.Sub(in.Previous.EnteredAt) < cfg.DirectGracePeriod {
			return out
		}
		var stale bool
		if in.Peer.LastHandshakeTime.IsZero() {
			stale = in.Now.Sub(in.Previous.EnteredAt) > cfg.DirectFailedAfter
		} else {
			stale = in.Now.Sub(in.Peer.LastHandshakeTime) > cfg.DirectFailedAfter
		}
		if stale {
			out.Mode = ModeRelayed
			out.EnteredAt = in.Now
		}
	case ModeRelayed:
		// Shadow peer's background handshake succeeded — direct is viable.
		if handshakeFresh {
			out.Mode = ModeDirect
			out.EnteredAt = in.Now
		}
	}
	return out
}
