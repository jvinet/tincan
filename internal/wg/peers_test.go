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
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir)
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
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir)
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
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if peer.PersistentKeepaliveInterval == nil || *peer.PersistentKeepaliveInterval != 25*time.Second {
			t.Fatalf("NAT self keepalive=%v", peer.PersistentKeepaliveInterval)
		}
	}

	self.Endpoint = "alice.example.com:51820"
	peers, err = BuildPeerConfigs(config.WireguardConfig{}, self, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if peer.PersistentKeepaliveInterval != nil {
			t.Fatalf("public self should not set keepalive: %v", peer.PersistentKeepaliveInterval)
		}
	}

	cfg := config.WireguardConfig{Keepalive: config.NewDuration(10 * time.Second)}
	peers, err = BuildPeerConfigs(cfg, self, dir)
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
	peers, err = BuildPeerConfigs(cfg, self, dir)
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
	if _, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir); err == nil {
		t.Fatal("expected invalid peer key error")
	}

	self, dir = peerFixture(t)
	dir.Nodes[1].TunnelIP = "not an ip"
	if _, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir); err == nil {
		t.Fatal("expected invalid tunnel IP error")
	}

	self, dir = peerFixture(t)
	dir.Nodes[1].Endpoint = "not-a-host-port"
	if _, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir); err == nil {
		t.Fatal("expected invalid endpoint error")
	}

	self, dir = peerFixture(t)
	dir.Nodes[2].Endpoint = ""
	dir.Nodes[2].ObservedEndpoint = "not-a-host-port"
	dir.Nodes[2].ObservedAt = time.Now()
	if _, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir); err == nil {
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
			got := chooseEndpoint(tc.node, now)
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
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir)
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
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir)
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
	peers, err := BuildPeerConfigs(config.WireguardConfig{}, self, dir)
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
	peers, err = BuildPeerConfigs(config.WireguardConfig{}, self, dir)
	if err != nil {
		t.Fatal(err)
	}
	if peers[0].PersistentKeepaliveInterval != nil {
		t.Fatalf("public self should not set keepalive")
	}
}
