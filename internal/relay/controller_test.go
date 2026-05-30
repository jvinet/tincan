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

	// First iteration: peer fresh; no relay yet (initial DIRECT, no tx growth).
	c.Update(self, dir, []wgtypes.Peer{
		{PublicKey: wgKey(t, peerPub), TransmitBytes: 100, LastHandshakeTime: now},
		{PublicKey: wgKey(t, relayPub), TransmitBytes: 100, LastHandshakeTime: now},
	}, now)

	// Advance time past DirectFailedAfter with growing tx, no handshake refresh.
	later := now.Add(3 * time.Minute)
	dec := c.Update(self, dir, []wgtypes.Peer{
		{PublicKey: wgKey(t, peerPub), TransmitBytes: 500, LastHandshakeTime: now}, // stale
		{PublicKey: wgKey(t, relayPub), TransmitBytes: 500, LastHandshakeTime: later},
	}, later)

	if !dec.Relayed[peerPub] {
		t.Fatalf("expected peer to be relayed after direct failure; states=%+v", dec.PeerStates)
	}
	if dec.Relayed[relayPub] {
		t.Fatalf("relay target should never be relayed; got %+v", dec.Relayed)
	}
}

func TestControllerNetChangedTriggersProbe(t *testing.T) {
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

	// Force peer into RELAYED by simulating direct failure.
	c.states[peerPub] = PeerState{Mode: ModeRelayed, EnteredAt: now}

	// Right after, with net change, we should probe direct.
	c.MarkNetChanged()
	dec := c.Update(self, dir, []wgtypes.Peer{
		{PublicKey: wgKey(t, peerPub)},
		{PublicKey: wgKey(t, relayPub)},
	}, now.Add(time.Second))

	if dec.Relayed[peerPub] {
		t.Fatalf("net change should have moved peer back to DIRECT; got relayed")
	}
	if dec.PeerStates[peerPub].Mode != ModeDirect {
		t.Fatalf("expected DIRECT mode after net change; got %v", dec.PeerStates[peerPub].Mode)
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
