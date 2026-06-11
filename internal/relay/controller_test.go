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

// mustAgeRecipient marks a test node as a tincan member: directory members
// without an AgeRecipient are plain-WireGuard spokes (Node.IsPlainWireGuard)
// and take the forced-relay path instead of the Decide state machine.
func mustAgeRecipient(t *testing.T) string {
	t.Helper()
	_, rcpt, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return rcpt
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
		{PublicKey: peerPub, TunnelIP: "10.42.0.2", AgeRecipient: mustAgeRecipient(t)},
		{PublicKey: relayPub, TunnelIP: "10.42.0.3", Endpoint: "relay.example.com:51820"},
	}}

	c := NewController(Config{})
	dec := c.Update(self, dir, nil, time.Now())

	if len(dec.Relayed) != 0 {
		t.Fatalf("admin/public node should not relay tincan peers; got %v", dec.Relayed)
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
		{PublicKey: peerPub, TunnelIP: "10.42.0.2", AgeRecipient: mustAgeRecipient(t)},
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
		{PublicKey: peerPub, TunnelIP: "10.42.0.2", AgeRecipient: mustAgeRecipient(t)},
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
	later := now.Add(5 * time.Minute)
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
		{PublicKey: peerPub, TunnelIP: "10.42.0.2", AgeRecipient: mustAgeRecipient(t)},
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

// A plain-WireGuard member (no AgeRecipient) is a hub-and-spoke spoke: only
// its hub can reach it directly. Every other node relays from the first
// iteration — no grace period, no failure detection — and a seemingly fresh
// handshake doesn't flip it back, because the mode is structural, not
// liveness-driven.
func TestControllerRelaysPlainWGSpokeImmediately(t *testing.T) {
	selfPub := mustWGKey(t)
	hubPub := mustWGKey(t)
	spokePub := mustWGKey(t)
	self := directory.Node{Name: "laptop", PublicKey: selfPub, TunnelIP: "10.42.0.3", AgeRecipient: mustAgeRecipient(t)}
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "hub", PublicKey: hubPub, TunnelIP: "10.42.0.1", Endpoint: "hub.example.com:51820", AgeRecipient: mustAgeRecipient(t)},
		self,
		{Name: "phone", PublicKey: spokePub, TunnelIP: "10.42.0.5"},
	}}

	c := NewController(Config{})
	now := time.Now()
	dec := c.Update(self, dir, nil, now)

	if !dec.Relayed[spokePub] {
		t.Fatalf("plain-WG spoke must be relayed on the first iteration; states=%+v", dec.PeerStates)
	}
	if dec.RelayTarget == nil || dec.RelayTarget.PublicKey != hubPub {
		t.Fatalf("relay target should be the spoke's hub; got %+v", dec.RelayTarget)
	}

	dec = c.Update(self, dir, []wgtypes.Peer{
		{PublicKey: wgKey(t, spokePub), LastHandshakeTime: now},
	}, now)
	if !dec.Relayed[spokePub] {
		t.Fatalf("spoke must stay relayed regardless of handshake state; states=%+v", dec.PeerStates)
	}
}

// A node with its own public endpoint skips relaying for tincan peers (they
// initiate inbound to it), but a plain-WG spoke never will — it must still be
// relayed via the spoke's hub.
func TestControllerRelaysPlainWGSpokeWhenSelfHasEndpoint(t *testing.T) {
	selfPub := mustWGKey(t)
	hubPub := mustWGKey(t)
	natPub := mustWGKey(t)
	spokePub := mustWGKey(t)
	self := directory.Node{Name: "public", PublicKey: selfPub, TunnelIP: "10.42.0.2", Endpoint: "public.example.com:51820", AgeRecipient: mustAgeRecipient(t)}
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "hub", PublicKey: hubPub, TunnelIP: "10.42.0.1", Endpoint: "hub.example.com:51820", AgeRecipient: mustAgeRecipient(t)},
		self,
		{Name: "laptop", PublicKey: natPub, TunnelIP: "10.42.0.3", AgeRecipient: mustAgeRecipient(t)},
		{Name: "phone", PublicKey: spokePub, TunnelIP: "10.42.0.5"},
	}}

	c := NewController(Config{})
	dec := c.Update(self, dir, nil, time.Now())

	if !dec.Relayed[spokePub] {
		t.Fatalf("spoke must be relayed even from a public node; got %+v", dec.Relayed)
	}
	if dec.Relayed[natPub] {
		t.Fatalf("tincan peer must stay direct on a public node; got %+v", dec.Relayed)
	}
	if dec.RelayTarget == nil || dec.RelayTarget.PublicKey != hubPub {
		t.Fatalf("relay target should be the spoke's hub; got %+v", dec.RelayTarget)
	}
}

// The hub is the one peer in a spoke's enrolled config, so from the hub's own
// vantage the spoke stays direct.
func TestControllerHubKeepsPlainWGSpokeDirect(t *testing.T) {
	hubPub := mustWGKey(t)
	spokePub := mustWGKey(t)
	self := directory.Node{Name: "hub", PublicKey: hubPub, TunnelIP: "10.42.0.1", Endpoint: "hub.example.com:51820", AgeRecipient: mustAgeRecipient(t)}
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{Name: "phone", PublicKey: spokePub, TunnelIP: "10.42.0.5"},
	}}

	c := NewController(Config{})
	dec := c.Update(self, dir, nil, time.Now())

	if dec.Relayed[spokePub] {
		t.Fatalf("hub must keep its spoke direct; got %+v", dec.Relayed)
	}
	if dec.PeerStates[spokePub].Mode != ModeDirect {
		t.Fatalf("expected DIRECT for spoke on its hub; got %v", dec.PeerStates[spokePub].Mode)
	}
}

// With no endpoint-bearing node anywhere there is no hub to relay through;
// the spoke is forced direct as the only (non-)option.
func TestControllerSpokeDirectWhenNoHubExists(t *testing.T) {
	selfPub := mustWGKey(t)
	spokePub := mustWGKey(t)
	self := directory.Node{Name: "laptop", PublicKey: selfPub, TunnelIP: "10.42.0.1", AgeRecipient: mustAgeRecipient(t)}
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{Name: "phone", PublicKey: spokePub, TunnelIP: "10.42.0.5"},
	}}

	c := NewController(Config{})
	dec := c.Update(self, dir, nil, time.Now())

	if len(dec.Relayed) != 0 {
		t.Fatalf("no hub: nothing to relay through; got %+v", dec.Relayed)
	}
}
