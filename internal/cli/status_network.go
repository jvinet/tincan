package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// networkNode is one row of the network roster: a directory node annotated
// with how it looks from the vantage of the node running the command.
type networkNode struct {
	Name           string `json:"name"`
	TunnelIP       string `json:"tunnel_ip"`
	Endpoint       string `json:"endpoint,omitempty"`
	EndpointSource string `json:"endpoint_source,omitempty"` // "configured" or "observed"
	Relay          bool   `json:"relay"`
	Self           bool   `json:"self"`
	// HasSession is whether this node is a WireGuard peer of the local node.
	// Tincan has no control plane, so handshake data exists only for peers the
	// local node itself talks to — there is no way to learn another node's
	// sessions. On a full-mesh admin that is every node; on a spoke it is just
	// the hub. A false HasSession means "this node and I don't peer", not "the
	// node is down".
	HasSession       bool       `json:"has_session"`
	LastHandshake    *time.Time `json:"last_handshake,omitempty"`
	LastHandshakeAge string     `json:"last_handshake_age,omitempty"`
}

type networkStatus struct {
	Self        string        `json:"self,omitempty"`
	Interface   string        `json:"interface"`
	NetworkCIDR string        `json:"network_cidr"`
	Serial      uint64        `json:"serial"`
	Nodes       []networkNode `json:"nodes"`
}

// runNetworkStatus renders the whole directory roster from the local node's
// vantage. It reads the applied cache (what this node is actually running, not
// a fresh drop fetch) and overlays the kernel's per-peer handshake times. It
// deliberately reports only what this node can observe: there is no control
// plane to poll peers, so handshake columns reflect the local node's sessions.
func runNetworkStatus(cfg *config.Config, asJSON bool) error {
	dir, _, err := cache.Read(cfg.Sync.StateDir)
	if err != nil {
		return fmt.Errorf("read cached directory (%w); run `tincan sync` first", err)
	}
	selfKey := cfg.Wireguard.PublicKey

	// Pull the kernel's peers so we can overlay handshake ages. A missing
	// interface (network down) is not fatal — the roster still shows the
	// directory; handshakes just read as "no session" everywhere.
	handshakeByKey := map[string]time.Time{}
	sessionKeys := map[string]bool{}
	if client, err := wgctrl.New(); err == nil {
		if dev, devErr := client.Device(cfg.Wireguard.Interface); devErr == nil {
			for _, p := range dev.Peers {
				key := p.PublicKey.String()
				sessionKeys[key] = true
				handshakeByKey[key] = p.LastHandshakeTime
			}
		}
		_ = client.Close()
	}

	status := networkStatus{
		Interface:   cfg.Wireguard.Interface,
		NetworkCIDR: dir.NetworkCIDR,
		Serial:      dir.Serial,
	}
	for _, node := range dir.Nodes {
		row := networkNode{
			Name:     node.Name,
			TunnelIP: node.TunnelIP,
			Relay:    node.Relay,
			Self:     node.PublicKey == selfKey,
		}
		if row.Self {
			status.Self = node.Name
		}
		if node.Endpoint != "" {
			row.Endpoint, row.EndpointSource = node.Endpoint, "configured"
		} else if node.ObservedEndpoint != "" {
			row.Endpoint, row.EndpointSource = node.ObservedEndpoint, "observed"
		}
		if !row.Self {
			row.HasSession = sessionKeys[node.PublicKey]
			if hs, ok := handshakeByKey[node.PublicKey]; ok && !hs.IsZero() {
				h := hs
				row.LastHandshake = &h
				row.LastHandshakeAge = time.Since(hs).Truncate(time.Second).String()
			}
		}
		status.Nodes = append(status.Nodes, row)
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(status)
	}
	printNetworkStatus(status)
	return nil
}

func networkRoleLabel(n networkNode) string {
	switch {
	case n.Self && n.Relay:
		return "self,relay"
	case n.Self:
		return "self"
	case n.Relay:
		return "relay"
	default:
		return "-"
	}
}

func networkEndpointLabel(n networkNode) string {
	if n.Endpoint == "" {
		return "-"
	}
	if n.EndpointSource == "observed" {
		return n.Endpoint + " (observed)"
	}
	return n.Endpoint
}

// networkHandshakeLabel reports the handshake age from this node's vantage.
// "—" for self, "no session" for a node the local node does not peer with
// (relay topology, or simply not a mutual peer), "never" for a configured peer
// that has not yet completed a handshake.
func networkHandshakeLabel(n networkNode) string {
	if n.Self {
		return "—"
	}
	if !n.HasSession {
		return "no session"
	}
	if n.LastHandshakeAge != "" {
		return n.LastHandshakeAge + " ago"
	}
	return "never"
}

func printNetworkStatus(s networkStatus) {
	p := newPrinter(os.Stdout)
	p.section("Network")
	pairs := []pair{
		kv("cidr", s.NetworkCIDR),
		kv("serial", fmt.Sprintf("%d", s.Serial)),
		kv("nodes", fmt.Sprintf("%d", len(s.Nodes))),
	}
	if s.Self != "" {
		pairs = append(pairs, kv("vantage", s.Self))
	}
	p.pairs(pairs...)
	p.blank()

	rows := [][]tableCell{{
		p.styledCell(ansiDim, "NODE"),
		p.styledCell(ansiDim, "IP"),
		p.styledCell(ansiDim, "ENDPOINT"),
		p.styledCell(ansiDim, "ROLE"),
		p.styledCell(ansiDim, "HANDSHAKE"),
	}}
	for _, n := range s.Nodes {
		rows = append(rows, []tableCell{
			plainCell(n.Name),
			plainCell(n.TunnelIP),
			plainCell(networkEndpointLabel(n)),
			plainCell(networkRoleLabel(n)),
			plainCell(networkHandshakeLabel(n)),
		})
	}
	p.table("  ", "  ", rows)
	p.blank()
	p.hint("Handshake ages are from this node's vantage; Tincan has no control plane, so a node it doesn't peer with shows \"no session\", not down.")
}
