package cli

import (
	"testing"

	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"github.com/jvinet/tincan/internal/wg"
)

func TestInitialRoutesCarryPlainWireGuardSpokesViaHub(t *testing.T) {
	cfg, dir := testFlowConfigAndDirectory(t, 1)
	_, hubKey, _ := keys.GenerateWGKeypair()
	_, spokeKey, _ := keys.GenerateWGKeypair()
	hub := directory.Node{Name: "hub", PublicKey: hubKey, TunnelIP: "10.42.0.2", AgeRecipient: dir.Nodes[0].AgeRecipient, Endpoint: "192.0.2.2:51820", Relay: true}
	spoke := directory.Node{Name: "phone", PublicKey: spokeKey, TunnelIP: "10.42.0.3"}
	dir.Nodes = append(dir.Nodes, hub, spoke)
	for _, scenario := range []struct{ selfEndpoint, spokeEndpoint string }{
		{},
		{selfEndpoint: "192.0.2.1:51820"},
		{spokeEndpoint: "192.0.2.3:51820"},
		{selfEndpoint: "192.0.2.1:51820", spokeEndpoint: "192.0.2.3:51820"},
	} {
		t.Run(scenario.selfEndpoint+"/"+scenario.spokeEndpoint, func(t *testing.T) {
			self := dir.Nodes[0]
			self.Endpoint = scenario.selfEndpoint
			dir.Nodes[0] = self
			dir.Nodes[2].Endpoint = scenario.spokeEndpoint
			peers, err := wg.BuildPeerConfigs(cfg.Wireguard, self, dir, initialRelayedPeers(self, dir), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, peer := range peers {
				switch peer.PublicKey.String() {
				case hubKey:
					if len(peer.AllowedIPs) != 2 || peer.AllowedIPs[1].IP.String() != spoke.TunnelIP {
						t.Fatalf("hub does not carry the spoke: %v", peer.AllowedIPs)
					}
				case spokeKey:
					if len(peer.AllowedIPs) != 0 || peer.Endpoint != nil || peer.PersistentKeepaliveInterval != nil {
						t.Fatal("spoke should be a bare shadow peer")
					}
				}
			}
		})
	}
	if initialRelayedPeers(hub, dir)[spokeKey] {
		t.Fatal("hub must route its own spoke directly")
	}
}
