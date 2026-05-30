// Package relay decides whether traffic to a NAT'd peer should flow direct
// (peer-to-peer over WireGuard) or be tunneled through an admin/relay node.
//
// The decision is per-(self, peer) and lives entirely on the client. Admin
// nodes can't observe peer-to-peer reachability — only handshakes against
// themselves — so each client watches its own wgctrl state, detects when the
// direct path is broken, and reshuffles AllowedIPs to route the peer's
// tunnel traffic through the relay node instead.
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
	// handshake (while we keep sending packets) before we declare the direct
	// path broken and fall back to the relay.
	DefaultDirectFailedAfter = 90 * time.Second

	// DefaultProbeInterval is how often a RELAYED peer is moved back to
	// DIRECT to retry the direct path. Explicit signals (peer's
	// ObservedEndpoint changed, local network changed) probe immediately.
	DefaultProbeInterval = 5 * time.Minute

	// DefaultDirectGracePeriod gives the kernel time to complete a handshake
	// after entering DIRECT before we evaluate liveness. Without this, a
	// freshly added peer (LastHandshakeTime=0) would be misjudged as broken.
	DefaultDirectGracePeriod = 30 * time.Second
)

type Config struct {
	DirectFailedAfter time.Duration
	ProbeInterval     time.Duration
	DirectGracePeriod time.Duration
}

func (c Config) withDefaults() Config {
	if c.DirectFailedAfter <= 0 {
		c.DirectFailedAfter = DefaultDirectFailedAfter
	}
	if c.ProbeInterval <= 0 {
		c.ProbeInterval = DefaultProbeInterval
	}
	if c.DirectGracePeriod <= 0 {
		c.DirectGracePeriod = DefaultDirectGracePeriod
	}
	return c
}

// PeerState is what Decide reads and writes between iterations. The caller
// (relay.Controller) owns the storage.
type PeerState struct {
	Mode                 Mode
	EnteredAt            time.Time
	LastTxBytes          int64
	LastObservedEndpoint string
}

// Inputs are the per-peer signals Decide needs to make a transition.
type Inputs struct {
	Now             time.Time
	Previous        PeerState
	Peer            wgtypes.Peer
	Node            directory.Node
	LocalNetChanged bool
}

// Decide returns the next PeerState given the previous one and the current
// observable inputs. It does not perform I/O.
func Decide(in Inputs, cfg Config) PeerState {
	cfg = cfg.withDefaults()
	out := in.Previous
	out.LastTxBytes = in.Peer.TransmitBytes
	out.LastObservedEndpoint = in.Node.ObservedEndpoint

	switch in.Previous.Mode {
	case ModeDirect:
		// Grace period after entering DIRECT: give the kernel time to handshake.
		if in.Now.Sub(in.Previous.EnteredAt) < cfg.DirectGracePeriod {
			return out
		}
		// Need fresh tx to have happened — otherwise the peer is idle, not broken.
		if in.Peer.TransmitBytes <= in.Previous.LastTxBytes {
			return out
		}
		broken := false
		if in.Peer.LastHandshakeTime.IsZero() {
			// Never handshook. If we've been trying past DirectFailedAfter, give up.
			broken = in.Now.Sub(in.Previous.EnteredAt) > cfg.DirectFailedAfter
		} else {
			broken = in.Now.Sub(in.Peer.LastHandshakeTime) > cfg.DirectFailedAfter
		}
		if broken {
			out.Mode = ModeRelayed
			out.EnteredAt = in.Now
		}
	case ModeRelayed:
		peerMoved := in.Node.ObservedEndpoint != "" &&
			in.Node.ObservedEndpoint != in.Previous.LastObservedEndpoint
		probeDue := in.Now.Sub(in.Previous.EnteredAt) > cfg.ProbeInterval
		if in.LocalNetChanged || peerMoved || probeDue {
			out.Mode = ModeDirect
			out.EnteredAt = in.Now
			// Reset LastTxBytes to current so the next iteration measures growth
			// from the moment we re-entered DIRECT.
			out.LastTxBytes = in.Peer.TransmitBytes
		}
	}
	return out
}
