package relay

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestDecideDirectStaysWhenHandshakeFresh(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeDirect,
			EnteredAt: now.Add(-time.Minute),
		},
		Peer: wgtypes.Peer{
			LastHandshakeTime: now.Add(-2 * time.Second),
		},
	}, Config{})
	if got.Mode != ModeDirect {
		t.Fatalf("Mode=%v want direct", got.Mode)
	}
}

func TestDecideDirectGracePeriodSuppressesEvaluation(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeDirect,
			EnteredAt: now.Add(-5 * time.Second), // well inside 30s grace
		},
		// no handshake at all yet
		Peer: wgtypes.Peer{},
	}, Config{})
	if got.Mode != ModeDirect {
		t.Fatalf("grace: Mode=%v want direct", got.Mode)
	}
}

func TestDecideDirectBecomesRelayedWhenHandshakeStale(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeDirect,
			EnteredAt: now.Add(-10 * time.Minute),
		},
		Peer: wgtypes.Peer{
			LastHandshakeTime: now.Add(-4 * time.Minute),
		},
	}, Config{})
	if got.Mode != ModeRelayed {
		t.Fatalf("Mode=%v want relayed", got.Mode)
	}
	if !got.EnteredAt.Equal(now) {
		t.Fatalf("EnteredAt=%v want %v", got.EnteredAt, now)
	}
}

func TestDecideDirectToleratesRekeyCadence(t *testing.T) {
	// A healthy WireGuard session re-handshakes only when the keypair
	// outlives REKEY_AFTER_TIME (120s), so handshake ages of ~2-2.5 minutes
	// are routine on a perfectly live path. Regression: a threshold below
	// that cadence demoted healthy pairs, and a one-sided demotion blackholes
	// the pair in both directions.
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeDirect,
			EnteredAt: now.Add(-time.Hour),
		},
		Peer: wgtypes.Peer{
			LastHandshakeTime: now.Add(-150 * time.Second),
		},
	}, Config{})
	if got.Mode != ModeDirect {
		t.Fatalf("Mode=%v want direct (150s handshake age is normal rekey cadence)", got.Mode)
	}
}

func TestDecideDirectBecomesRelayedWhenNeverHandshookPastFailure(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeDirect,
			EnteredAt: now.Add(-4 * time.Minute), // past DirectFailedAfter (180s)
		},
		Peer: wgtypes.Peer{},
	}, Config{})
	if got.Mode != ModeRelayed {
		t.Fatalf("Mode=%v want relayed", got.Mode)
	}
}

func TestDecideRelayedStaysWhenShadowHandshakeStale(t *testing.T) {
	// Shadow peer has never succeeded; we stay in RELAYED indefinitely until
	// either a handshake completes (kernel-driven keepalive) or the peer is
	// removed from the directory.
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeRelayed,
			EnteredAt: now.Add(-time.Hour),
		},
		Peer: wgtypes.Peer{}, // no handshake
	}, Config{})
	if got.Mode != ModeRelayed {
		t.Fatalf("Mode=%v want relayed (no probe handshake yet)", got.Mode)
	}
}

func TestDecideRelayedFlipsToDirectWhenShadowHandshakeSucceeds(t *testing.T) {
	// The kernel's background keepalive on the shadow peer just completed a
	// fresh handshake — direct is viable, flip back.
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeRelayed,
			EnteredAt: now.Add(-10 * time.Minute),
		},
		Peer: wgtypes.Peer{
			LastHandshakeTime: now.Add(-5 * time.Second),
		},
	}, Config{})
	if got.Mode != ModeDirect {
		t.Fatalf("Mode=%v want direct (shadow handshake)", got.Mode)
	}
	if !got.EnteredAt.Equal(now) {
		t.Fatalf("EnteredAt should be reset to now; got %v", got.EnteredAt)
	}
}

func TestDecideRelayedStaysWhenHandshakeAgeOlderThanFailure(t *testing.T) {
	// A LastHandshakeTime older than DirectFailedAfter does not count as
	// "fresh" — could be a stale session from before we entered RELAYED.
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeRelayed,
			EnteredAt: now.Add(-time.Hour),
		},
		Peer: wgtypes.Peer{
			LastHandshakeTime: now.Add(-5 * time.Minute),
		},
	}, Config{})
	if got.Mode != ModeRelayed {
		t.Fatalf("Mode=%v want relayed (stale handshake)", got.Mode)
	}
}
