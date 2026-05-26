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

func BuildPeerConfigs(cfg config.WireguardConfig, self directory.Node, dir directory.Directory) ([]wgtypes.PeerConfig, error) {
	selfHasEndpoint := self.Endpoint != ""
	keepalive := time.Duration(0)
	if cfg.Keepalive.Set {
		keepalive = cfg.Keepalive.Duration
	} else if !selfHasEndpoint {
		keepalive = 25 * time.Second
	}
	peers := make([]wgtypes.PeerConfig, 0, len(dir.Nodes)-1)
	for _, node := range dir.Nodes {
		if node.PublicKey == self.PublicKey {
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
		if node.Endpoint != "" {
			endpoint, err := net.ResolveUDPAddr("udp", node.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("resolve peer %q endpoint %q: %w", node.Name, node.Endpoint, err)
			}
			peer.Endpoint = endpoint
		}
		if keepalive > 0 {
			ka := keepalive
			peer.PersistentKeepaliveInterval = &ka
		}
		peers = append(peers, peer)
	}
	return peers, nil
}
