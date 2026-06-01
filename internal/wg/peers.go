//go:build linux

package wg

import (
	"fmt"
	"net"
	"time"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LANEndpointLookup returns a learned LAN endpoint (host:port) for the
// given peer pubkey, or "" if none is known/usable. Pass nil to
// BuildPeerConfigs to disable LAN preference entirely.
type LANEndpointLookup func(pubkey string) string

// BuildPeerConfigs translates the directory into a list of WireGuard
// PeerConfigs for self's interface. When relayed is non-empty, the listed
// peers (by public key string) become "shadow peers": their tunnel IPs are
// folded into the relay target's AllowedIPs (so data routes through the
// relay), but they are still configured as peers themselves — with empty
// AllowedIPs, plus their endpoint and keepalive. The kernel keeps trying
// background handshakes on those shadow peers; when one succeeds, the
// daemon observes a fresh LastHandshakeTime via wgctrl and flips the peer
// back to DIRECT (just reshuffling AllowedIPs — no peer add/remove).
//
// The relay target is the first non-self node in the directory with a
// public Endpoint set. If relayed is empty or no relay target exists,
// every peer in the directory gets its own AllowedIPs and behaves
// directly.
//
// lanLookup, when non-nil, is consulted to obtain a per-peer LAN endpoint
// learned via the discovery package. LAN endpoints rank above
// admin-observed endpoints but below operator-configured ones in
// chooseEndpoint's precedence.
func BuildPeerConfigs(cfg config.WireguardConfig, self directory.Node, dir directory.Directory, relayed map[string]bool, lanLookup LANEndpointLookup) ([]wgtypes.PeerConfig, error) {
	selfHasEndpoint := self.Endpoint != ""
	keepalive := time.Duration(0)
	if cfg.Keepalive.Set {
		keepalive = cfg.Keepalive.Duration
	} else if !selfHasEndpoint {
		keepalive = 25 * time.Second
	}

	var relayTargetKey string
	if len(relayed) > 0 {
		for i := range dir.Nodes {
			if dir.Nodes[i].PublicKey == self.PublicKey {
				continue
			}
			if dir.Nodes[i].Endpoint != "" {
				relayTargetKey = dir.Nodes[i].PublicKey
				break
			}
		}
	}

	peers := make([]wgtypes.PeerConfig, 0, len(dir.Nodes)-1)
	var extraAllowedIPs []net.IPNet
	relayTargetIdx := -1

	for _, node := range dir.Nodes {
		if node.PublicKey == self.PublicKey {
			continue
		}
		pub, err := keys.ParseWGPublic(node.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %q: %w", node.Name, err)
		}
		_, tunnel, err := net.ParseCIDR(node.TunnelIP + "/32")
		if err != nil {
			return nil, fmt.Errorf("peer %q tunnel IP: %w", node.Name, err)
		}
		shadow := relayed[node.PublicKey] && relayTargetKey != "" && node.PublicKey != relayTargetKey
		peer := wgtypes.PeerConfig{
			PublicKey:         pub,
			ReplaceAllowedIPs: true,
		}
		if shadow {
			peer.AllowedIPs = []net.IPNet{}
			extraAllowedIPs = append(extraAllowedIPs, *tunnel)
		} else {
			peer.AllowedIPs = []net.IPNet{*tunnel}
		}
		endpointStr := chooseEndpoint(node, lanLookup)
		if endpointStr != "" {
			endpoint, err := net.ResolveUDPAddr("udp", endpointStr)
			if err != nil {
				return nil, fmt.Errorf("resolve peer %q endpoint %q: %w", node.Name, endpointStr, err)
			}
			peer.Endpoint = endpoint
		}
		if keepalive > 0 {
			ka := keepalive
			peer.PersistentKeepaliveInterval = &ka
		}
		if node.PublicKey == relayTargetKey {
			relayTargetIdx = len(peers)
		}
		peers = append(peers, peer)
	}

	if relayTargetIdx >= 0 && len(extraAllowedIPs) > 0 {
		peers[relayTargetIdx].AllowedIPs = append(peers[relayTargetIdx].AllowedIPs, extraAllowedIPs...)
	}
	return peers, nil
}

func chooseEndpoint(node directory.Node, lanLookup LANEndpointLookup) string {
	if node.Endpoint != "" {
		return node.Endpoint
	}
	if lanLookup != nil {
		if lan := lanLookup(node.PublicKey); lan != "" {
			return lan
		}
	}
	// An admin-observed endpoint is trusted for as long as it remains in the
	// directory. There is no client-side staleness TTL: the publishing admin
	// clears ObservedEndpoint once a peer stops handshaking, and a dead
	// endpoint is recovered via relay (handshake-driven), not by expiry here.
	return node.ObservedEndpoint
}
