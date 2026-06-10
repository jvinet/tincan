package relay

import (
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustWGKey(t *testing.T) string {
	t.Helper()
	_, pub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func wgKey(t *testing.T, b64 string) wgtypes.Key {
	t.Helper()
	k, err := keys.ParseWGPublic(b64)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestControllerSkipsRelayWhenSelfHasEndpoint(t *testing.T) {
	selfPub := mustWGKey(t)
	peerPub := mustWGKey(t)
	relayPub := mustWGKey(t)
	self := directory.Node{PublicKey: selfPub, TunnelIP: "10.42.0.1", Endpoint: "self.example.com:51820"}
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{PublicKey: peerPub, TunnelIP: "10.42.0.2"},
		{PublicKey: relayPub, TunnelIP: "10.42.0.3", Endpoint: "relay.example.com:51820"},
	}}

	c := NewController(Config{})
	dec := c.Update(self, dir, nil, time.Now())

	if len(dec.Relayed) != 0 {
		t.Fatalf("admin/public node should not relay; got %v", dec.Relayed)
	}
}

// The controller's relay target must honor the explicit Relay flag, choosing a
// marked node over an earlier endpoint-bearing one — and it must match what
// wg.BuildPeerConfigs picks, or routing diverges from the relay decision.
func TestControllerPrefersMarkedRelay(t *testing.T) {
	selfPub := mustWGKey(t)
	firstPub := mustWGKey(t)
	markedPub := mustWGKey(t)
	self := directory.Node{PublicKey: selfPub, TunnelIP: "10.42.0.1"}
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{PublicKey: firstPub, TunnelIP: "10.42.0.2", Endpoint: "first.example.com:51820"},
		{PublicKey: markedPub, TunnelIP: "10.42.0.3", Endpoint: "relay.example.com:51820", Relay: true},
	}}

	c := NewController(Config{})
	dec := c.Update(self, dir, nil, time.Now())
	if dec.RelayTarget == nil || dec.RelayTarget.PublicKey != markedPub {
		t.Fatalf("expected the marked relay as target, got %+v", dec.RelayTarget)
	}
}

func TestControllerSkipsWhenNoRelayTarget(t *testing.T) {
	selfPub := mustWGKey(t)
	peerPub := mustWGKey(t)
	self := directory.Node{PublicKey: selfPub, TunnelIP: "10.42.0.1"}
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{PublicKey: peerPub, TunnelIP: "10.42.0.2"},
	}}

	c := NewController(Config{})
	dec := c.Update(self, dir, nil, time.Now())

	if len(dec.Relayed) != 0 {
		t.Fatalf("no relay target: got %v", dec.Relayed)
	}
	if dec.RelayTarget != nil {
		t.Fatalf("expected nil relay target, got %+v", dec.RelayTarget)
	}
}

func TestControllerRelaysAfterDirectFailure(t *testing.T) {
	selfPub := mustWGKey(t)
	peerPub := mustWGKey(t)
	relayPub := mustWGKey(t)
	self := directory.Node{PublicKey: selfPub, TunnelIP: "10.42.0.1"}
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{PublicKey: peerPub, TunnelIP: "10.42.0.2"},
		{PublicKey: relayPub, TunnelIP: "10.42.0.3", Endpoint: "relay.example.com:51820"},
	}}

	c := NewController(Config{})
	now := time.Now()

	// First iteration: peer fresh; no relay yet (initial DIRECT, in grace).
	c.Update(self, dir, []wgtypes.Peer{
		{PublicKey: wgKey(t, peerPub), LastHandshakeTime: now},
		{PublicKey: wgKey(t, relayPub), LastHandshakeTime: now},
	}, now)

	// Advance time past DirectFailedAfter with no handshake refresh.
	later := now.Add(3 * time.Minute)
	dec := c.Update(self, dir, []wgtypes.Peer{
		{PublicKey: wgKey(t, peerPub), LastHandshakeTime: now}, // stale
		{PublicKey: wgKey(t, relayPub), LastHandshakeTime: later},
	}, later)

	if !dec.Relayed[peerPub] {
		t.Fatalf("expected peer to be relayed after direct failure; states=%+v", dec.PeerStates)
	}
	if dec.Relayed[relayPub] {
		t.Fatalf("relay target should never be relayed; got %+v", dec.Relayed)
	}
}

func TestControllerRelayedFlipsBackOnShadowHandshake(t *testing.T) {
	// Once a kernel-driven shadow-peer handshake succeeds, the controller
	// should immediately flip back to DIRECT without waiting for a timer.
	selfPub := mustWGKey(t)
	peerPub := mustWGKey(t)
	relayPub := mustWGKey(t)
	self := directory.Node{PublicKey: selfPub, TunnelIP: "10.42.0.1"}
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{PublicKey: peerPub, TunnelIP: "10.42.0.2"},
		{PublicKey: relayPub, TunnelIP: "10.42.0.3", Endpoint: "relay.example.com:51820"},
	}}

	c := NewController(Config{})
	now := time.Now()
	c.states[peerPub] = PeerState{Mode: ModeRelayed, EnteredAt: now.Add(-10 * time.Minute)}

	dec := c.Update(self, dir, []wgtypes.Peer{
		{PublicKey: wgKey(t, peerPub), LastHandshakeTime: now.Add(-5 * time.Second)},
		{PublicKey: wgKey(t, relayPub), LastHandshakeTime: now},
	}, now)

	if dec.Relayed[peerPub] {
		t.Fatalf("shadow handshake should flip back to DIRECT; got relayed")
	}
	if dec.PeerStates[peerPub].Mode != ModeDirect {
		t.Fatalf("expected DIRECT mode after shadow handshake; got %v", dec.PeerStates[peerPub].Mode)
	}
}

func TestControllerDropsStaleStateForRemovedNode(t *testing.T) {
	selfPub := mustWGKey(t)
	peerPub := mustWGKey(t)
	relayPub := mustWGKey(t)
	self := directory.Node{PublicKey: selfPub, TunnelIP: "10.42.0.1"}

	c := NewController(Config{})
	c.states[peerPub] = PeerState{Mode: ModeRelayed, EnteredAt: time.Now()}

	// Directory no longer contains the peer.
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{PublicKey: relayPub, TunnelIP: "10.42.0.3", Endpoint: "relay.example.com:51820"},
	}}
	c.Update(self, dir, nil, time.Now())

	if _, ok := c.states[peerPub]; ok {
		t.Fatalf("removed peer state should be dropped from controller")
	}
}
