package relay

import (
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestDecideDirectStaysWhenHandshakeFresh(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:        ModeDirect,
			EnteredAt:   now.Add(-time.Minute),
			LastTxBytes: 100,
		},
		Peer: wgtypes.Peer{
			TransmitBytes:     500,
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
		Peer: wgtypes.Peer{
			TransmitBytes: 1000,
			// no handshake at all yet
		},
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
			Mode:        ModeDirect,
			EnteredAt:   now.Add(-3 * time.Minute),
			LastTxBytes: 100,
		},
		Peer: wgtypes.Peer{
			TransmitBytes:     500, // grew
			LastHandshakeTime: now.Add(-2 * time.Minute),
		},
	}, Config{})
	if got.Mode != ModeRelayed {
		t.Fatalf("Mode=%v want relayed", got.Mode)
	}
	if !got.EnteredAt.Equal(now) {
		t.Fatalf("EnteredAt=%v want %v", got.EnteredAt, now)
	}
}

func TestDecideDirectBecomesRelayedWhenNeverHandshookPastFailure(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:        ModeDirect,
			EnteredAt:   now.Add(-2 * time.Minute), // past DirectFailedAfter (90s)
			LastTxBytes: 100,
		},
		Peer: wgtypes.Peer{
			TransmitBytes: 500, // grew — keepalive going out
			// LastHandshakeTime zero
		},
	}, Config{})
	if got.Mode != ModeRelayed {
		t.Fatalf("Mode=%v want relayed", got.Mode)
	}
}

func TestDecideDirectStaysWhenIdleEvenIfHandshakeOld(t *testing.T) {
	// No tx growth → we aren't actively sending, so we can't tell whether the
	// path is broken. Don't preemptively relay idle peers.
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:        ModeDirect,
			EnteredAt:   now.Add(-3 * time.Minute),
			LastTxBytes: 500,
		},
		Peer: wgtypes.Peer{
			TransmitBytes:     500, // unchanged
			LastHandshakeTime: now.Add(-10 * time.Minute),
		},
	}, Config{})
	if got.Mode != ModeDirect {
		t.Fatalf("Mode=%v want direct (idle)", got.Mode)
	}
}

func TestDecideRelayedProbeAfterInterval(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeRelayed,
			EnteredAt: now.Add(-6 * time.Minute), // past ProbeInterval
		},
		Peer: wgtypes.Peer{TransmitBytes: 1000},
	}, Config{})
	if got.Mode != ModeDirect {
		t.Fatalf("Mode=%v want direct (probe)", got.Mode)
	}
	if !got.EnteredAt.Equal(now) {
		t.Fatalf("EnteredAt should reset on probe; got %v", got.EnteredAt)
	}
	if got.LastTxBytes != 1000 {
		t.Fatalf("LastTxBytes should reset to current; got %d", got.LastTxBytes)
	}
}

func TestDecideRelayedProbesOnPeerMove(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:                 ModeRelayed,
			EnteredAt:            now.Add(-30 * time.Second), // not probe-due yet
			LastObservedEndpoint: "1.2.3.4:5000",
		},
		Node: directory.Node{ObservedEndpoint: "5.6.7.8:5000"},
	}, Config{})
	if got.Mode != ModeDirect {
		t.Fatalf("Mode=%v want direct (peer moved)", got.Mode)
	}
}

func TestDecideRelayedProbesOnLocalNetChange(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:      ModeRelayed,
			EnteredAt: now.Add(-30 * time.Second),
		},
		LocalNetChanged: true,
	}, Config{})
	if got.Mode != ModeDirect {
		t.Fatalf("Mode=%v want direct (local net changed)", got.Mode)
	}
}

func TestDecideRelayedStaysWithoutSignal(t *testing.T) {
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:                 ModeRelayed,
			EnteredAt:            now.Add(-time.Minute),
			LastObservedEndpoint: "1.2.3.4:5000",
		},
		Node: directory.Node{ObservedEndpoint: "1.2.3.4:5000"},
	}, Config{})
	if got.Mode != ModeRelayed {
		t.Fatalf("Mode=%v want relayed (no trigger)", got.Mode)
	}
}

func TestDecideObservedEndpointTrackedAcrossIterations(t *testing.T) {
	// Verify that LastObservedEndpoint is stored every iteration so we can
	// detect a change between observation publishes.
	now := time.Now()
	got := Decide(Inputs{
		Now: now,
		Previous: PeerState{
			Mode:                 ModeDirect,
			EnteredAt:            now.Add(-time.Minute),
			LastObservedEndpoint: "",
		},
		Peer: wgtypes.Peer{TransmitBytes: 100, LastHandshakeTime: now},
		Node: directory.Node{ObservedEndpoint: "1.2.3.4:5000"},
	}, Config{})
	if got.LastObservedEndpoint != "1.2.3.4:5000" {
		t.Fatalf("LastObservedEndpoint=%q want %q", got.LastObservedEndpoint, "1.2.3.4:5000")
	}
}
