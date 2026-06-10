//go:build linux

package wg

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPreserveLiveEndpoints(t *testing.T) {
	keyA, _ := wgtypes.GeneratePrivateKey()
	keyB, _ := wgtypes.GeneratePrivateKey()
	keyC, _ := wgtypes.GeneratePrivateKey()
	keyD, _ := wgtypes.GeneratePrivateKey()
	pubA, pubB, pubC, pubD := keyA.PublicKey(), keyB.PublicKey(), keyC.PublicKey(), keyD.PublicKey()
	now := time.Now()
	ep := func(port int) *net.UDPAddr {
		return &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: port}
	}

	peers := []wgtypes.PeerConfig{
		{PublicKey: pubA, Endpoint: ep(1)}, // fresh handshake → endpoint dropped
		{PublicKey: pubB, Endpoint: ep(2)}, // stale handshake → endpoint pushed
		{PublicKey: pubC, Endpoint: ep(3)}, // never handshaked → endpoint pushed
		{PublicKey: pubD},                  // no endpoint pick → untouched
	}
	kernel := []wgtypes.Peer{
		// pubA roamed to a source address the directory has never seen; its
		// fresh handshake proves that path works.
		{PublicKey: pubA, LastHandshakeTime: now.Add(-30 * time.Second), Endpoint: &net.UDPAddr{IP: net.ParseIP("192.168.68.60"), Port: 35569}},
		{PublicKey: pubB, LastHandshakeTime: now.Add(-5 * time.Minute)},
		{PublicKey: pubC},
		{PublicKey: pubD, LastHandshakeTime: now.Add(-time.Second)},
	}

	got := preserveLiveEndpoints(peers, kernel, now)

	if got[0].Endpoint != nil {
		t.Fatalf("fresh-handshake peer endpoint should be dropped, got %v", got[0].Endpoint)
	}
	if got[1].Endpoint == nil || got[1].Endpoint.Port != 2 {
		t.Fatalf("stale-handshake peer endpoint should be pushed, got %v", got[1].Endpoint)
	}
	if got[2].Endpoint == nil || got[2].Endpoint.Port != 3 {
		t.Fatalf("never-handshaked peer endpoint should be pushed, got %v", got[2].Endpoint)
	}
	if got[3].Endpoint != nil {
		t.Fatalf("peer without endpoint pick should stay nil, got %v", got[3].Endpoint)
	}
}

func TestPreserveLiveEndpointsUnknownKernelPeer(t *testing.T) {
	key, _ := wgtypes.GeneratePrivateKey()
	pub := key.PublicKey()
	peers := []wgtypes.PeerConfig{
		{PublicKey: pub, Endpoint: &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51820}},
	}
	got := preserveLiveEndpoints(peers, nil, time.Now())
	if got[0].Endpoint == nil {
		t.Fatal("endpoint for a peer not yet in the kernel must be pushed")
	}
}
