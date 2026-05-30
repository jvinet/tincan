package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/daemon"
	"github.com/jvinet/tincan/internal/directory"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type StatusCmd struct {
	JSON bool `help:"Emit status as JSON."`
}

type statusOutput struct {
	Name       string                 `json:"name"`
	Interface  string                 `json:"interface"`
	TunnelIP   string                 `json:"tunnel_ip,omitempty"`
	Cache      map[string]interface{} `json:"cache"`
	Daemon     map[string]interface{} `json:"daemon"`
	Drop       map[string]interface{} `json:"drop"`
	WireGuard  map[string]interface{} `json:"wireguard"`
	NATWarning string                 `json:"nat_warning,omitempty"`
}

type statusPeer struct {
	PublicKey           string     `json:"public_key"`
	Name                string     `json:"name,omitempty"`
	Mode                string     `json:"mode,omitempty"` // "direct", "relayed", or empty when unknown
	RelayVia            string     `json:"relay_via,omitempty"`
	Endpoint            string     `json:"endpoint,omitempty"`
	DirectoryEndpoint   string     `json:"directory_endpoint,omitempty"`
	ObservedEndpoint    string     `json:"observed_endpoint,omitempty"`
	ObservedAt          *time.Time `json:"observed_at,omitempty"`
	AllowedIPs          []string   `json:"allowed_ips"`
	LastHandshake       *time.Time `json:"last_handshake,omitempty"`
	LastHandshakeAge    string     `json:"last_handshake_age,omitempty"`
	ReceiveBytes        int64      `json:"receive_bytes"`
	TransmitBytes       int64      `json:"transmit_bytes"`
	PersistentKeepalive string     `json:"persistent_keepalive,omitempty"`
}

func (c *StatusCmd) Run(ctx context.Context, g *Globals) error {
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	out := statusOutput{
		Name:      cfg.Wireguard.Name,
		Interface: cfg.Wireguard.Interface,
		Cache:     map[string]interface{}{},
		Daemon:    map[string]interface{}{},
		Drop:      map[string]interface{}{},
		WireGuard: map[string]interface{}{},
	}
	nodesByPubkey := map[string]directory.Node{}
	if dir, _, err := cache.Read(cfg.Sync.Cache); err == nil {
		out.Cache["serial"] = dir.Serial
		out.Cache["path"] = cfg.Sync.Cache
		for _, node := range dir.Nodes {
			nodesByPubkey[node.PublicKey] = node
		}
		if self, err := findSelf(cfg, dir); err == nil {
			out.TunnelIP = self.TunnelIP
			if self.Endpoint == "" {
				anyPeerReachable := false
				for _, node := range dir.Nodes {
					if node.PublicKey == self.PublicKey {
						continue
					}
					if node.Endpoint != "" || node.ObservedEndpoint != "" {
						anyPeerReachable = true
						break
					}
				}
				if !anyPeerReachable && len(dir.Nodes) > 1 {
					out.NATWarning = "self and all peers lack endpoints; enable [observe] on the admin or add a relay"
				}
			}
		}
	} else {
		out.Cache["error"] = err.Error()
	}
	if state, err := cache.ReadState(cfg.Sync.Cache); err == nil {
		out.Cache["last_sync"] = state.LastSync
		out.Cache["age"] = time.Since(state.LastSync).Truncate(time.Second).String()
		out.Cache["etag"] = state.LastETag
	}
	if pid, err := daemon.ReadPID(cfg.Sync.PIDFile); err == nil {
		out.Daemon["pid"] = pid
		out.Daemon["alive"] = daemon.PIDAlive(pid)
	} else {
		out.Daemon["alive"] = false
		out.Daemon["error"] = err.Error()
	}
	if d, err := loadReadDrop(cfg); err == nil {
		statCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		meta, statErr := d.Stat(statCtx)
		cancel()
		out.Drop["name"] = d.Name()
		out.Drop["reachable"] = statErr == nil
		if statErr == nil {
			out.Drop["size"] = meta.Size
			out.Drop["updated_at"] = meta.UpdatedAt
			out.Drop["etag"] = meta.ETag
		} else {
			out.Drop["error"] = statErr.Error()
		}
	} else {
		out.Drop["reachable"] = false
		out.Drop["error"] = err.Error()
	}
	dir, _, _ := cache.Read(cfg.Sync.Cache)
	self, _ := findSelf(cfg, dir)
	if client, err := wgctrl.New(); err == nil {
		dev, devErr := client.Device(cfg.Wireguard.Interface)
		_ = client.Close()
		if devErr == nil {
			out.WireGuard["public_key"] = dev.PublicKey.String()
			out.WireGuard["listen_port"] = dev.ListenPort
			out.WireGuard["peer_count"] = len(dev.Peers)
			out.WireGuard["peers"] = wireGuardPeerStatus(dev.Peers, dir, self)
			out.WireGuard["type"] = dev.Type.String()
		} else {
			out.WireGuard["error"] = devErr.Error()
		}
	} else {
		out.WireGuard["error"] = err.Error()
	}
	if c.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	printStatusText(out)
	return nil
}

func peerLabel(peer statusPeer) string {
	if peer.Name != "" {
		return peer.Name
	}
	if len(peer.PublicKey) > 12 {
		return peer.PublicKey[:8] + "…"
	}
	return peer.PublicKey
}

func peerEndpointLabel(peer statusPeer) string {
	if peer.Mode == "relayed" {
		if peer.RelayVia != "" {
			return "via " + peer.RelayVia
		}
		return "via relay"
	}
	if peer.Endpoint != "" {
		return peer.Endpoint
	}
	if peer.DirectoryEndpoint != "" {
		return peer.DirectoryEndpoint + " (configured)"
	}
	if peer.ObservedEndpoint != "" {
		suffix := "observed"
		if peer.ObservedAt != nil {
			suffix = "observed " + time.Since(*peer.ObservedAt).Truncate(time.Second).String() + " ago"
		}
		return peer.ObservedEndpoint + " (" + suffix + ")"
	}
	return "-"
}

func wireGuardPeerStatus(peers []wgtypes.Peer, dir directory.Directory, self directory.Node) []statusPeer {
	nodesByPubkey := make(map[string]directory.Node, len(dir.Nodes))
	for _, node := range dir.Nodes {
		nodesByPubkey[node.PublicKey] = node
	}
	peerByPubkey := make(map[string]wgtypes.Peer, len(peers))
	for _, p := range peers {
		peerByPubkey[p.PublicKey.String()] = p
	}

	// Identify the relay target. Same rule as the daemon: first non-self node
	// in directory with a public Endpoint set.
	var relayTarget *directory.Node
	for i := range dir.Nodes {
		if dir.Nodes[i].PublicKey == self.PublicKey {
			continue
		}
		if dir.Nodes[i].Endpoint != "" {
			relayTarget = &dir.Nodes[i]
			break
		}
	}

	// Build the set of tunnel IPs that the relay target's wgctrl peer covers
	// beyond its own tunnel IP. Those map to relayed directory nodes.
	relayedByTunnelIP := make(map[string]bool)
	if relayTarget != nil {
		if relayPeer, ok := peerByPubkey[relayTarget.PublicKey]; ok {
			for _, allowed := range relayPeer.AllowedIPs {
				ip := allowed.IP.String()
				if ip == relayTarget.TunnelIP {
					continue
				}
				relayedByTunnelIP[ip] = true
			}
		}
	}

	status := make([]statusPeer, 0, len(peers))
	seen := make(map[string]bool, len(peers))
	for _, peer := range peers {
		allowedIPs := make([]string, 0, len(peer.AllowedIPs))
		for _, allowedIP := range peer.AllowedIPs {
			allowedIPs = append(allowedIPs, allowedIP.String())
		}
		pubkey := peer.PublicKey.String()
		seen[pubkey] = true
		item := statusPeer{
			PublicKey:     pubkey,
			Mode:          "direct",
			AllowedIPs:    allowedIPs,
			ReceiveBytes:  peer.ReceiveBytes,
			TransmitBytes: peer.TransmitBytes,
		}
		if node, ok := nodesByPubkey[pubkey]; ok {
			item.Name = node.Name
			item.DirectoryEndpoint = node.Endpoint
			item.ObservedEndpoint = node.ObservedEndpoint
			if !node.ObservedAt.IsZero() {
				observedAt := node.ObservedAt
				item.ObservedAt = &observedAt
			}
		}
		if peer.Endpoint != nil {
			item.Endpoint = peer.Endpoint.String()
		}
		if !peer.LastHandshakeTime.IsZero() {
			lastHandshake := peer.LastHandshakeTime
			item.LastHandshake = &lastHandshake
			item.LastHandshakeAge = time.Since(lastHandshake).Truncate(time.Second).String()
		}
		if peer.PersistentKeepaliveInterval > 0 {
			item.PersistentKeepalive = peer.PersistentKeepaliveInterval.String()
		}
		status = append(status, item)
	}

	// Synthesize entries for directory nodes that the daemon has folded into
	// the relay target's AllowedIPs (i.e. peers we route via the relay).
	if relayTarget != nil {
		for _, node := range dir.Nodes {
			if node.PublicKey == self.PublicKey || seen[node.PublicKey] {
				continue
			}
			if !relayedByTunnelIP[node.TunnelIP] {
				continue
			}
			item := statusPeer{
				PublicKey:  node.PublicKey,
				Name:       node.Name,
				Mode:       "relayed",
				RelayVia:   relayTarget.Name,
				AllowedIPs: []string{node.TunnelIP + "/32"},
			}
			if node.Endpoint != "" {
				item.DirectoryEndpoint = node.Endpoint
			}
			if node.ObservedEndpoint != "" {
				item.ObservedEndpoint = node.ObservedEndpoint
			}
			if !node.ObservedAt.IsZero() {
				observedAt := node.ObservedAt
				item.ObservedAt = &observedAt
			}
			status = append(status, item)
		}
	}
	return status
}

func printStatusText(out statusOutput) {
	p := newPrinter(os.Stdout)

	p.section("Node")
	nodePairs := []pair{
		kv("name", out.Name),
		kv("interface", out.Interface),
	}
	if out.TunnelIP != "" {
		nodePairs = append(nodePairs, kv("tunnel IP", out.TunnelIP))
	}
	p.pairs(nodePairs...)
	p.blank()

	p.section("Cache")
	p.pairs(statusCachePairs(out.Cache)...)
	p.blank()

	p.section("Daemon")
	p.pairs(statusDaemonPairs(out.Daemon)...)
	p.blank()

	p.section("Drop")
	p.pairs(statusDropPairs(out.Drop)...)
	p.blank()

	p.section("WireGuard")
	p.pairs(statusWireguardPairs(out.WireGuard)...)

	if peers, ok := out.WireGuard["peers"].([]statusPeer); ok && len(peers) > 0 {
		p.blank()
		p.section("Peers")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  "+p.style(ansiDim, "PEER\tENDPOINT\tALLOWED IPS\tLAST HANDSHAKE\tRX\tTX\tKEEPALIVE"))
		for _, peer := range peers {
			handshake := "-"
			if peer.LastHandshake != nil {
				handshake = peer.LastHandshake.Format(time.RFC3339)
				if peer.LastHandshakeAge != "" {
					handshake += " (" + peer.LastHandshakeAge + " ago)"
				}
			}
			keepalive := peer.PersistentKeepalive
			if keepalive == "" {
				keepalive = "-"
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%d\t%d\t%s\n",
				peerLabel(peer), peerEndpointLabel(peer), strings.Join(peer.AllowedIPs, ","), handshake, peer.ReceiveBytes, peer.TransmitBytes, keepalive)
		}
		_ = w.Flush()
	}
	if out.NATWarning != "" {
		p.blank()
		p.warn("%s", out.NATWarning)
	}
}

func statusCachePairs(m map[string]interface{}) []pair {
	pairs := []pair{}
	if v, ok := m["serial"].(uint64); ok {
		pairs = append(pairs, kv("serial", fmt.Sprintf("%d", v)))
	}
	if v, ok := m["path"].(string); ok && v != "" {
		pairs = append(pairs, kv("path", v))
	}
	if v, ok := m["last_sync"].(time.Time); ok {
		pairs = append(pairs, kv("last sync", v.Format(time.RFC3339)))
	}
	if v, ok := m["age"].(string); ok && v != "" {
		pairs = append(pairs, kv("age", v))
	}
	if v, ok := m["etag"].(string); ok && v != "" {
		pairs = append(pairs, kv("etag", v))
	}
	if v, ok := m["error"].(string); ok && v != "" {
		pairs = append(pairs, kv("error", v))
	}
	return pairs
}

func statusDaemonPairs(m map[string]interface{}) []pair {
	pairs := []pair{}
	if v, ok := m["pid"].(int); ok {
		pairs = append(pairs, kv("pid", fmt.Sprintf("%d", v)))
	}
	if v, ok := m["alive"].(bool); ok {
		pairs = append(pairs, kv("alive", fmt.Sprintf("%t", v)))
	}
	if v, ok := m["error"].(string); ok && v != "" {
		pairs = append(pairs, kv("error", v))
	}
	return pairs
}

func statusDropPairs(m map[string]interface{}) []pair {
	pairs := []pair{}
	if v, ok := m["name"].(string); ok && v != "" {
		pairs = append(pairs, kv("name", v))
	}
	if v, ok := m["reachable"].(bool); ok {
		pairs = append(pairs, kv("reachable", fmt.Sprintf("%t", v)))
	}
	if v, ok := m["size"].(int64); ok {
		pairs = append(pairs, kv("size", fmt.Sprintf("%d bytes", v)))
	}
	if v, ok := m["updated_at"].(time.Time); ok {
		pairs = append(pairs, kv("updated at", v.Format(time.RFC3339)))
	}
	if v, ok := m["etag"].(string); ok && v != "" {
		pairs = append(pairs, kv("etag", v))
	}
	if v, ok := m["error"].(string); ok && v != "" {
		pairs = append(pairs, kv("error", v))
	}
	return pairs
}

func statusWireguardPairs(m map[string]interface{}) []pair {
	pairs := []pair{}
	if v, ok := m["public_key"].(string); ok && v != "" {
		pairs = append(pairs, kv("public key", v))
	}
	if v, ok := m["listen_port"].(int); ok {
		pairs = append(pairs, kv("listen port", fmt.Sprintf("%d", v)))
	}
	if v, ok := m["type"].(string); ok && v != "" {
		pairs = append(pairs, kv("type", v))
	}
	if v, ok := m["peer_count"].(int); ok {
		pairs = append(pairs, kv("peer count", fmt.Sprintf("%d", v)))
	}
	if v, ok := m["error"].(string); ok && v != "" {
		pairs = append(pairs, kv("error", v))
	}
	return pairs
}
