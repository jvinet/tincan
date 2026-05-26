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
	Endpoint            string     `json:"endpoint,omitempty"`
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
	if dir, _, err := cache.Read(cfg.Sync.Cache); err == nil {
		out.Cache["serial"] = dir.Serial
		out.Cache["path"] = cfg.Sync.Cache
		if self, err := findSelf(cfg, dir); err == nil {
			out.TunnelIP = self.TunnelIP
			if self.Endpoint == "" {
				allPeersNAT := true
				for _, node := range dir.Nodes {
					if node.PublicKey != self.PublicKey && node.Endpoint != "" {
						allPeersNAT = false
						break
					}
				}
				if allPeersNAT && len(dir.Nodes) > 1 {
					out.NATWarning = "self and all peers lack endpoints; pure NAT-to-NAT cannot form a mesh without a relay"
				}
			}
		}
	} else {
		out.Cache["error"] = err.Error()
	}
	if state, err := cache.ReadState(cfg.Sync.Cache); err == nil {
		out.Cache["last_sync"] = state.LastSync
		out.Cache["age"] = time.Since(state.LastSync).String()
		out.Cache["etag"] = state.LastETag
	}
	if pid, err := daemon.ReadPID(cfg.Sync.PIDFile); err == nil {
		out.Daemon["pid"] = pid
		out.Daemon["alive"] = daemon.PIDAlive(pid)
	} else {
		out.Daemon["alive"] = false
		out.Daemon["error"] = err.Error()
	}
	if d, err := loadDrop(cfg); err == nil {
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
	if client, err := wgctrl.New(); err == nil {
		dev, devErr := client.Device(cfg.Wireguard.Interface)
		_ = client.Close()
		if devErr == nil {
			out.WireGuard["public_key"] = dev.PublicKey.String()
			out.WireGuard["listen_port"] = dev.ListenPort
			out.WireGuard["peer_count"] = len(dev.Peers)
			out.WireGuard["peers"] = wireGuardPeerStatus(dev.Peers)
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

func wireGuardPeerStatus(peers []wgtypes.Peer) []statusPeer {
	status := make([]statusPeer, 0, len(peers))
	for _, peer := range peers {
		allowedIPs := make([]string, 0, len(peer.AllowedIPs))
		for _, allowedIP := range peer.AllowedIPs {
			allowedIPs = append(allowedIPs, allowedIP.String())
		}
		item := statusPeer{
			PublicKey:     peer.PublicKey.String(),
			AllowedIPs:    allowedIPs,
			ReceiveBytes:  peer.ReceiveBytes,
			TransmitBytes: peer.TransmitBytes,
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
	return status
}

func printStatusText(out statusOutput) {
	fmt.Printf("node: %s\n", out.Name)
	fmt.Printf("interface: %s\n", out.Interface)
	if out.TunnelIP != "" {
		fmt.Printf("tunnel IP: %s\n", out.TunnelIP)
	}
	fmt.Printf("cache: %v\n", out.Cache)
	fmt.Printf("daemon: %v\n", out.Daemon)
	fmt.Printf("drop: %v\n", out.Drop)
	fmt.Printf("wireguard: public_key=%v listen_port=%v type=%v peer_count=%v\n",
		out.WireGuard["public_key"], out.WireGuard["listen_port"], out.WireGuard["type"], out.WireGuard["peer_count"])
	if errText, ok := out.WireGuard["error"].(string); ok && errText != "" {
		fmt.Printf("wireguard error: %s\n", errText)
	}
	if peers, ok := out.WireGuard["peers"].([]statusPeer); ok && len(peers) > 0 {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PEER\tENDPOINT\tALLOWED IPS\tLAST HANDSHAKE\tRX BYTES\tTX BYTES\tKEEPALIVE")
		for _, peer := range peers {
			handshake := "-"
			if peer.LastHandshake != nil {
				handshake = peer.LastHandshake.Format(time.RFC3339)
				if peer.LastHandshakeAge != "" {
					handshake += " (" + peer.LastHandshakeAge + " ago)"
				}
			}
			endpoint := peer.Endpoint
			if endpoint == "" {
				endpoint = "-"
			}
			keepalive := peer.PersistentKeepalive
			if keepalive == "" {
				keepalive = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
				peer.PublicKey, endpoint, strings.Join(peer.AllowedIPs, ","), handshake, peer.ReceiveBytes, peer.TransmitBytes, keepalive)
		}
		_ = w.Flush()
	}
	if out.NATWarning != "" {
		fmt.Printf("warning: %s\n", out.NATWarning)
	}
}
