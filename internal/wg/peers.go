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

const ObservedEndpointTTL = 30 * time.Minute

// BuildPeerConfigs translates the directory into a list of WireGuard
// PeerConfigs for self's interface. When relayed is non-empty, the listed
// peers (by public key string) are omitted from the peer list and their
// tunnel IPs are folded into the relay target's AllowedIPs so traffic to
// them flows through the relay.
//
// The relay target is the first non-self node in the directory with a
// public Endpoint set. If relayed is empty or no relay target exists,
// every peer in the directory gets its own peer entry — i.e. the function
// behaves exactly as it did before the relay feature.
func BuildPeerConfigs(cfg config.WireguardConfig, self directory.Node, dir directory.Directory, relayed map[string]bool) ([]wgtypes.PeerConfig, error) {
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
		if relayed[node.PublicKey] && relayTargetKey != "" && node.PublicKey != relayTargetKey {
			_, extraIP, err := net.ParseCIDR(node.TunnelIP + "/32")
			if err != nil {
				return nil, fmt.Errorf("relayed peer %q tunnel IP: %w", node.Name, err)
			}
			extraAllowedIPs = append(extraAllowedIPs, *extraIP)
			continue
		}
		pub, err := keys.ParseWGPublic(node.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %q: %w", node.Name, err)
		}
		_, allowedIP, err := net.ParseCIDR(node.TunnelIP + "/32")
		if err != nil {
			return nil, fmt.Errorf("peer %q tunnel IP: %w", node.Name, err)
		}
		peer := wgtypes.PeerConfig{
			PublicKey:         pub,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{*allowedIP},
		}
		endpointStr := chooseEndpoint(node, time.Now())
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

func chooseEndpoint(node directory.Node, now time.Time) string {
	if node.Endpoint != "" {
		return node.Endpoint
	}
	if node.ObservedEndpoint == "" || node.ObservedAt.IsZero() {
		return ""
	}
	if now.Sub(node.ObservedAt) > ObservedEndpointTTL {
		return ""
	}
	return node.ObservedEndpoint
}
