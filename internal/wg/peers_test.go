//go:build linux

package wg

import (
	"net"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustPubKey(t *testing.T) string {
	t.Helper()
	_, pub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func peerFixture(t *testing.T) (directory.Node, directory.Directory) {
	t.Helper()
	self := directory.Node{Name: "alice", PublicKey: mustPubKey(t), TunnelIP: "10.42.0.1"}
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{Name: "bob", PublicKey: mustPubKey(t), TunnelIP: "10.42.0.2", Endpoint: "127.0.0.1:51820"},
		{Name: "carol", PublicKey: mustPubKey(t), TunnelIP: "10.42.0.3"},
	}}
	return self, dir
}

func peerByAllowedIP(peers []wgtypes.PeerConfig, ip string) *wgtypes.PeerConfig {
	for i := range peers {
		if len(peers[i].AllowedIPs) > 0 && peers[i].AllowedIPs[0].IP.String() == ip {
			return &peers[i]
		}
	}
	return nil
}

func TestBuildPeerConfigsSelfSkippedAndAllowedIPs(t *testing.T) {
	self, dir := peerFixture(t)
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("peers=%d", len(peers))
	}
	for _, peer := range peers {
		if peer.PublicKey.String() == self.PublicKey {
			t.Fatal("self was included in peer list")
		}
		if len(peer.AllowedIPs) != 1 {
			t.Fatalf("allowed IP count=%d", len(peer.AllowedIPs))
		}
		ones, bits := peer.AllowedIPs[0].Mask.Size()
		if ones != 32 || bits != 32 {
			t.Fatalf("allowed IP mask=/%d bits=%d", ones, bits)
		}
		if !peer.ReplaceAllowedIPs {
			t.Fatal("ReplaceAllowedIPs must be true")
		}
	}
}

func TestBuildPeerConfigsEndpointResolved(t *testing.T) {
	self, dir := peerFixture(t)
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	bob := peerByAllowedIP(peers, "10.42.0.2")
	if bob == nil || bob.Endpoint == nil {
		t.Fatalf("bob endpoint missing: %+v", bob)
	}
	if !bob.Endpoint.IP.Equal(net.ParseIP("127.0.0.1")) || bob.Endpoint.Port != 51820 {
		t.Fatalf("bob endpoint=%v", bob.Endpoint)
	}
	carol := peerByAllowedIP(peers, "10.42.0.3")
	if carol == nil || carol.Endpoint != nil {
		t.Fatalf("carol endpoint should be nil: %+v", carol)
	}
}

func TestBuildPeerConfigsKeepaliveDefaultsAndOverrides(t *testing.T) {
	self, dir := peerFixture(t)
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if peer.PersistentKeepaliveInterval == nil || *peer.PersistentKeepaliveInterval != 25*time.Second {
			t.Fatalf("NAT self keepalive=%v", peer.PersistentKeepaliveInterval)
		}
	}

	self.Endpoint = "alice.example.com:51820"
	peers, err = BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if peer.PersistentKeepaliveInterval != nil {
			t.Fatalf("public self should not set keepalive: %v", peer.PersistentKeepaliveInterval)
		}
	}

	cfg := config.WireguardConfig{Keepalive: config.NewDuration(10 * time.Second)}
	peers, err = BuildPeerConfigs(cfg, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if peer.PersistentKeepaliveInterval == nil || *peer.PersistentKeepaliveInterval != 10*time.Second {
			t.Fatalf("override keepalive=%v", peer.PersistentKeepaliveInterval)
		}
	}

	self.Endpoint = ""
	cfg = config.WireguardConfig{Keepalive: config.NewDuration(0)}
	peers, err = BuildPeerConfigs(cfg, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if peer.PersistentKeepaliveInterval != nil {
			t.Fatalf("explicit zero should disable keepalive: %v", peer.PersistentKeepaliveInterval)
		}
	}
}

func TestBuildPeerConfigsRejectsBadPeerData(t *testing.T) {
	self, dir := peerFixture(t)
	dir.Nodes[1].PublicKey = "not a key"
	if _, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil); err == nil {
		t.Fatal("expected invalid peer key error")
	}

	self, dir = peerFixture(t)
	dir.Nodes[1].TunnelIP = "not an ip"
	if _, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil); err == nil {
		t.Fatal("expected invalid tunnel IP error")
	}

	self, dir = peerFixture(t)
	dir.Nodes[1].Endpoint = "not-a-host-port"
	if _, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil); err == nil {
		t.Fatal("expected invalid endpoint error")
	}

	self, dir = peerFixture(t)
	dir.Nodes[2].Endpoint = ""
	dir.Nodes[2].ObservedEndpoint = "not-a-host-port"
	dir.Nodes[2].ObservedAt = time.Now()
	if _, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil); err == nil {
		t.Fatal("expected invalid observed endpoint error")
	}
}

func TestChooseEndpoint(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-ObservedEndpointTTL / 2)
	stale := now.Add(-ObservedEndpointTTL - time.Second)

	cases := []struct {
		name string
		node directory.Node
		want string
	}{
		{
			name: "configured wins over observed",
			node: directory.Node{Endpoint: "host:1234", ObservedEndpoint: "203.0.113.7:5555", ObservedAt: fresh},
			want: "host:1234",
		},
		{
			name: "observed used when configured empty and fresh",
			node: directory.Node{ObservedEndpoint: "203.0.113.7:5555", ObservedAt: fresh},
			want: "203.0.113.7:5555",
		},
		{
			name: "observed ignored when stale",
			node: directory.Node{ObservedEndpoint: "203.0.113.7:5555", ObservedAt: stale},
			want: "",
		},
		{
			name: "observed ignored when ObservedAt zero",
			node: directory.Node{ObservedEndpoint: "203.0.113.7:5555"},
			want: "",
		},
		{
			name: "no observed endpoint",
			node: directory.Node{},
			want: "",
		},
		{
			name: "observed fresh at exact TTL boundary",
			node: directory.Node{ObservedEndpoint: "203.0.113.7:5555", ObservedAt: now.Add(-ObservedEndpointTTL)},
			want: "203.0.113.7:5555",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := chooseEndpoint(tc.node, now, nil)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestChooseEndpointLANPrecedence(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-ObservedEndpointTTL / 2)

	pk := "PEER-PUBKEY"
	lan := func(p string) string {
		if p == pk {
			return "192.168.1.42:51820"
		}
		return ""
	}

	cases := []struct {
		name string
		node directory.Node
		want string
	}{
		{
			name: "operator endpoint still wins over LAN",
			node: directory.Node{PublicKey: pk, Endpoint: "host:1234", ObservedEndpoint: "203.0.113.7:5555", ObservedAt: fresh},
			want: "host:1234",
		},
		{
			name: "LAN preferred over observed when operator empty",
			node: directory.Node{PublicKey: pk, ObservedEndpoint: "203.0.113.7:5555", ObservedAt: fresh},
			want: "192.168.1.42:51820",
		},
		{
			name: "LAN used even when observed is empty",
			node: directory.Node{PublicKey: pk},
			want: "192.168.1.42:51820",
		},
		{
			name: "no LAN for unknown peer falls back to observed",
			node: directory.Node{PublicKey: "other-pubkey", ObservedEndpoint: "203.0.113.7:5555", ObservedAt: fresh},
			want: "203.0.113.7:5555",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := chooseEndpoint(tc.node, now, lan)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestBuildPeerConfigsAppliesObservedEndpoint(t *testing.T) {
	self, dir := peerFixture(t)
	dir.Nodes[2].Endpoint = ""
	dir.Nodes[2].ObservedEndpoint = "127.0.0.1:51900"
	dir.Nodes[2].ObservedAt = time.Now()
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	carol := peerByAllowedIP(peers, "10.42.0.3")
	if carol == nil || carol.Endpoint == nil {
		t.Fatalf("carol endpoint missing: %+v", carol)
	}
	if !carol.Endpoint.IP.Equal(net.ParseIP("127.0.0.1")) || carol.Endpoint.Port != 51900 {
		t.Fatalf("carol endpoint=%v", carol.Endpoint)
	}
}

func TestBuildPeerConfigsIgnoresStaleObservedEndpoint(t *testing.T) {
	self, dir := peerFixture(t)
	dir.Nodes[2].Endpoint = ""
	dir.Nodes[2].ObservedEndpoint = "127.0.0.1:51900"
	dir.Nodes[2].ObservedAt = time.Now().Add(-ObservedEndpointTTL - time.Minute)
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	carol := peerByAllowedIP(peers, "10.42.0.3")
	if carol == nil {
		t.Fatal("carol peer missing")
	}
	if carol.Endpoint != nil {
		t.Fatalf("stale observed endpoint should be ignored, got %v", carol.Endpoint)
	}
}

func TestBuildPeerConfigsKeepaliveAndAllowedIPs(t *testing.T) {
	_, selfPub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, peerPub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	self := directory.Node{Name: "alice", PublicKey: selfPub, TunnelIP: "10.42.0.1"}
	dir := directory.Directory{Nodes: []directory.Node{
		self,
		{Name: "bob", PublicKey: peerPub, TunnelIP: "10.42.0.2"},
	}}
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("peers=%d", len(peers))
	}
	if peers[0].AllowedIPs[0].String() != "10.42.0.2/32" {
		t.Fatalf("allowed IPs=%v", peers[0].AllowedIPs)
	}
	if peers[0].PersistentKeepaliveInterval == nil || *peers[0].PersistentKeepaliveInterval != 25*time.Second {
		t.Fatalf("keepalive=%v", peers[0].PersistentKeepaliveInterval)
	}
	self.Endpoint = "vpn.example.com:51820"
	peers, err = BuildPeerConfigs(config.WireguardConfig{}, self, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if peers[0].PersistentKeepaliveInterval != nil {
		t.Fatalf("public self should not set keepalive")
	}
}

func TestAppendDeletionsMarksAbsentPeers(t *testing.T) {
	keyA, _ := wgtypes.GeneratePrivateKey()
	keyB, _ := wgtypes.GeneratePrivateKey()
	keyC, _ := wgtypes.GeneratePrivateKey()
	pubA, pubB, pubC := keyA.PublicKey(), keyB.PublicKey(), keyC.PublicKey()

	target := []wgtypes.PeerConfig{
		{PublicKey: pubA},
		{PublicKey: pubB},
	}
	existing := []wgtypes.Peer{
		{PublicKey: pubA},
		{PublicKey: pubC},
	}

	got := appendDeletions(target, existing)

	if len(got) != 3 {
		t.Fatalf("len=%d want 3", len(got))
	}
	removed := got[2]
	if removed.PublicKey != pubC {
		t.Fatalf("removed peer key=%s want %s", removed.PublicKey, pubC)
	}
	if !removed.Remove {
		t.Fatalf("absent peer not marked Remove: %+v", removed)
	}
	for _, p := range got[:2] {
		if p.Remove {
			t.Fatalf("present peer marked Remove: %+v", p)
		}
	}
}

func TestBuildPeerConfigsRelayFoldsAllowedIPs(t *testing.T) {
	// self (alice) is NAT'd; bob is the relay target (has Endpoint); carol is
	// another NAT'd peer that we've decided to relay. carol stays in the peer
	// list as a "shadow" peer (empty AllowedIPs, but live endpoint+keepalive)
	// so the kernel keeps probing direct reachability in the background.
	self, dir := peerFixture(t)
	dir.Nodes[2].ObservedEndpoint = "203.0.113.10:5555"
	dir.Nodes[2].ObservedAt = time.Now()
	relayed := map[string]bool{dir.Nodes[2].PublicKey: true} // carol

	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, relayed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("relayed peer should remain as shadow peer; peers=%d (%+v)", len(peers), peers)
	}
	var bob, carol *wgtypes.PeerConfig
	for i := range peers {
		switch peers[i].PublicKey.String() {
		case dir.Nodes[1].PublicKey:
			bob = &peers[i]
		case dir.Nodes[2].PublicKey:
			carol = &peers[i]
		}
	}
	if bob == nil || carol == nil {
		t.Fatalf("missing peers: bob=%v carol=%v", bob, carol)
	}
	if len(bob.AllowedIPs) != 2 {
		t.Fatalf("bob (relay) should carry 2 AllowedIPs (self + carol); got %+v", bob.AllowedIPs)
	}
	if bob.AllowedIPs[0].IP.String() != "10.42.0.2" || bob.AllowedIPs[1].IP.String() != "10.42.0.3" {
		t.Fatalf("bob AllowedIPs=%v want [10.42.0.2 10.42.0.3]", bob.AllowedIPs)
	}
	if len(carol.AllowedIPs) != 0 {
		t.Fatalf("carol (shadow) should have empty AllowedIPs; got %+v", carol.AllowedIPs)
	}
	if carol.Endpoint == nil || carol.Endpoint.IP.String() != "203.0.113.10" || carol.Endpoint.Port != 5555 {
		t.Fatalf("carol shadow peer should keep its endpoint for kernel probes; got %v", carol.Endpoint)
	}
	if carol.PersistentKeepaliveInterval == nil || *carol.PersistentKeepaliveInterval != 25*time.Second {
		t.Fatalf("carol shadow peer should keep keepalive (drives the probe); got %v", carol.PersistentKeepaliveInterval)
	}
}

func TestBuildPeerConfigsRelaySkippedWhenNoTarget(t *testing.T) {
	// No node has a public Endpoint, so even though relayed is non-empty we
	// can't relay — fall back to direct peer entries.
	self, dir := peerFixture(t)
	dir.Nodes[1].Endpoint = ""
	relayed := map[string]bool{dir.Nodes[2].PublicKey: true}

	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, relayed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("no relay target → all peers direct; got %d", len(peers))
	}
}

func TestBuildPeerConfigsRelayDoesNotRelayTheTarget(t *testing.T) {
	// Even if a buggy caller marks the relay target as relayed, the function
	// must keep the target as a peer (otherwise we'd lose admin connectivity).
	self, dir := peerFixture(t)
	relayed := map[string]bool{
		dir.Nodes[1].PublicKey: true, // bob, the relay target
		dir.Nodes[2].PublicKey: true, // carol
	}

	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir, relayed, nil)
	if err != nil {
		t.Fatal(err)
	}
	hasBob := false
	for _, p := range peers {
		if p.PublicKey.String() == dir.Nodes[1].PublicKey {
			hasBob = true
		}
	}
	if !hasBob {
		t.Fatalf("relay target must remain a peer even if marked relayed")
	}
}
