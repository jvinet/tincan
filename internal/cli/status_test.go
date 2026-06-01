package cli

import (
	"net"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPeerLabelPrefersName(t *testing.T) {
	cases := []struct {
		name string
		peer statusPeer
		want string
	}{
		{
			name: "name set",
			peer: statusPeer{PublicKey: "abcdefghijklmnopqrstuvwxyz", Name: "bob"},
			want: "bob",
		},
		{
			name: "long pubkey, no name",
			peer: statusPeer{PublicKey: "abcdefghijklmnopqrstuvwxyz"},
			want: "abcdefgh…",
		},
		{
			name: "short pubkey, no name",
			peer: statusPeer{PublicKey: "abcdef"},
			want: "abcdef",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerLabel(tc.peer); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestPeerEndpointLabelPriority(t *testing.T) {
	observedAt := time.Now().Add(-2 * time.Minute)

	cases := []struct {
		name     string
		peer     statusPeer
		contains string
		exact    string
	}{
		{
			name:  "wgctrl wins (public)",
			peer:  statusPeer{Endpoint: "198.51.100.42:51820", DirectoryEndpoint: "ignored", ObservedEndpoint: "203.0.113.7:5555"},
			exact: "198.51.100.42:51820",
		},
		{
			name:  "wgctrl private endpoint shown raw (lan/wan distinction now in STATUS)",
			peer:  statusPeer{Endpoint: "192.168.1.42:51820"},
			exact: "192.168.1.42:51820",
		},
		{
			name:  "directory configured shown when wgctrl missing",
			peer:  statusPeer{DirectoryEndpoint: "alice.example.com:51820"},
			exact: "alice.example.com:51820 (configured)",
		},
		{
			name:     "observed shown with age when only observation",
			peer:     statusPeer{ObservedEndpoint: "203.0.113.7:5555", ObservedAt: &observedAt},
			contains: "203.0.113.7:5555 (observed ",
		},
		{
			name:  "observed shown without age when no timestamp",
			peer:  statusPeer{ObservedEndpoint: "203.0.113.7:5555"},
			exact: "203.0.113.7:5555 (observed)",
		},
		{
			name:  "dash when nothing known",
			peer:  statusPeer{},
			exact: "-",
		},
		{
			name:  "relayed peer with kernel endpoint shows that endpoint (status column carries via X)",
			peer:  statusPeer{Mode: "relayed", RelayVia: "zf", Endpoint: "203.0.113.7:5555"},
			exact: "203.0.113.7:5555",
		},
		{
			name:  "relayed peer with no kernel endpoint falls through to dash",
			peer:  statusPeer{Mode: "relayed", RelayVia: "zf"},
			exact: "-",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := peerEndpointLabel(tc.peer)
			if tc.exact != "" && got != tc.exact {
				t.Fatalf("got %q want %q", got, tc.exact)
			}
			if tc.contains != "" && !startsWith(got, tc.contains) {
				t.Fatalf("got %q want prefix %q", got, tc.contains)
			}
		})
	}
}

func TestPeerStatusLabel(t *testing.T) {
	cases := []struct {
		name string
		peer statusPeer
		want string
	}{
		{
			name: "direct public endpoint",
			peer: statusPeer{Mode: "direct", Endpoint: "198.51.100.42:51820"},
			want: "DIRECT",
		},
		{
			name: "direct private endpoint labeled LAN",
			peer: statusPeer{Mode: "direct", Endpoint: "192.168.1.42:51820"},
			want: "LAN",
		},
		{
			name: "direct ULA endpoint labeled LAN",
			peer: statusPeer{Mode: "direct", Endpoint: "[fc00::1]:51820"},
			want: "LAN",
		},
		{
			name: "direct without endpoint",
			peer: statusPeer{Mode: "direct"},
			want: "DIRECT",
		},
		{
			name: "empty mode treated as direct",
			peer: statusPeer{Endpoint: "198.51.100.42:51820"},
			want: "DIRECT",
		},
		{
			name: "relayed with target",
			peer: statusPeer{Mode: "relayed", RelayVia: "zf"},
			want: "RELAYED via zf",
		},
		{
			name: "relayed without target",
			peer: statusPeer{Mode: "relayed"},
			want: "RELAYED",
		},
		{
			name: "relayed beats LAN even when probing private endpoint",
			peer: statusPeer{Mode: "relayed", RelayVia: "zf", Endpoint: "192.168.1.42:51820"},
			want: "RELAYED via zf",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerStatusLabel(tc.peer); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestPeerHandshakeLabel(t *testing.T) {
	cases := []struct {
		name string
		peer statusPeer
		want string
	}{
		{name: "with age", peer: statusPeer{LastHandshakeAge: "53s"}, want: "53s ago"},
		{name: "no age", peer: statusPeer{}, want: "never"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerHandshakeLabel(tc.peer); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestWireGuardPeerStatusDetectsShadowPeerAsRelayed(t *testing.T) {
	relayKey, _ := wgKeyForTest()
	otherKey, _ := wgKeyForTest()
	selfKey, _ := wgKeyForTest()

	self := directory.Node{PublicKey: selfKey, TunnelIP: "10.42.0.1"}
	relayNode := directory.Node{Name: "zf", PublicKey: relayKey, TunnelIP: "10.42.0.2", Endpoint: "zf.example.com:51820"}
	otherNode := directory.Node{Name: "kilo", PublicKey: otherKey, TunnelIP: "10.42.0.3"}
	dir := directory.Directory{Nodes: []directory.Node{self, relayNode, otherNode}}

	// Simulate the daemon's RELAYED configuration: relay target carries both
	// /32s, the relayed peer is present as a shadow peer with empty AllowedIPs.
	parsedRelayKey, err := keys.ParseWGPublic(relayKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedOtherKey, err := keys.ParseWGPublic(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	_, ip1, _ := net.ParseCIDR("10.42.0.2/32")
	_, ip2, _ := net.ParseCIDR("10.42.0.3/32")
	peers := []wgtypes.Peer{
		{PublicKey: parsedRelayKey, AllowedIPs: []net.IPNet{*ip1, *ip2}},
		{PublicKey: parsedOtherKey, AllowedIPs: nil},
	}

	status := wireGuardPeerStatus(peers, dir, self)
	if len(status) != 2 {
		t.Fatalf("len=%d want 2 (relay + shadow)", len(status))
	}
	var relayed *statusPeer
	for i := range status {
		if status[i].PublicKey == otherKey {
			relayed = &status[i]
		}
	}
	if relayed == nil {
		t.Fatalf("shadow peer not found: %+v", status)
	}
	if relayed.Mode != "relayed" {
		t.Fatalf("mode=%q want relayed", relayed.Mode)
	}
	if relayed.RelayVia != "zf" {
		t.Fatalf("via=%q want zf", relayed.RelayVia)
	}
}

func wgKeyForTest() (string, error) {
	_, pub, err := keys.GenerateWGKeypair()
	return pub, err
}
