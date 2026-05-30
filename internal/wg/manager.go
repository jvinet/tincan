//go:build linux

package wg

import (
	"fmt"
	"time"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Manager struct {
	iface      string
	privateKey wgtypes.Key
	listenPort *int
	mtu        int
	wg         config.WireguardConfig
}

func NewManager(cfg config.WireguardConfig) (*Manager, error) {
	priv, err := keys.ParseWGPrivate(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	var listenPort *int
	if cfg.ListenPort > 0 {
		listenPort = &cfg.ListenPort
	}
	if cfg.Interface == "" {
		cfg.Interface = config.DefaultInterface
	}
	if cfg.MTU == 0 {
		cfg.MTU = config.DefaultMTU
	}
	return &Manager{iface: cfg.Interface, privateKey: priv, listenPort: listenPort, mtu: cfg.MTU, wg: cfg}, nil
}

func (m *Manager) Up() error {
	link, err := m.ensureLink()
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set link up: %w", err)
	}
	return nil
}

func (m *Manager) Apply(self directory.Node, dir directory.Directory, relayed map[string]bool) error {
	link, err := netlink.LinkByName(m.iface)
	if err != nil {
		return fmt.Errorf("find link %q: %w", m.iface, err)
	}
	peers, err := BuildPeerConfigs(m.wg, self, dir, relayed)
	if err != nil {
		return err
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wgctrl: %w", err)
	}
	defer client.Close()
	peers = mergeAgainstKernel(client, m.iface, peers)
	if err := client.ConfigureDevice(m.iface, wgtypes.Config{
		PrivateKey:   &m.privateKey,
		ListenPort:   m.listenPort,
		ReplacePeers: false,
		Peers:        peers,
	}); err != nil {
		return fmt.Errorf("configure WireGuard device: %w", err)
	}
	if err := ensureAddress(link, self.TunnelIP); err != nil {
		return err
	}
	if err := ensureRoute(link, dir.NetworkCIDR); err != nil {
		return err
	}
	return nil
}

func (m *Manager) Ensure(self directory.Node, dir directory.Directory, relayed map[string]bool) error {
	if err := m.Up(); err != nil {
		return err
	}
	return m.Apply(self, dir, relayed)
}

// mergeAgainstKernel adapts a freshly-built peer list for use with
// ReplacePeers=false: it normalizes nil keepalive durations to an explicit
// zero (so the kernel reliably picks up role changes) and appends Remove
// entries for any peer currently in the kernel that no longer appears in the
// directory. Using ReplacePeers=false preserves kernel-tracked state
// (LastHandshakeTime, source-learned endpoints) across reconcile loops, which
// the admin's endpoint observation depends on.
func mergeAgainstKernel(client *wgctrl.Client, iface string, peers []wgtypes.PeerConfig) []wgtypes.PeerConfig {
	zero := time.Duration(0)
	for i := range peers {
		if peers[i].PersistentKeepaliveInterval == nil {
			peers[i].PersistentKeepaliveInterval = &zero
		}
	}
	dev, err := client.Device(iface)
	if err != nil {
		return peers
	}
	return appendDeletions(peers, dev.Peers)
}

func appendDeletions(target []wgtypes.PeerConfig, existing []wgtypes.Peer) []wgtypes.PeerConfig {
	keep := make(map[wgtypes.Key]bool, len(target))
	for _, p := range target {
		keep[p.PublicKey] = true
	}
	for _, p := range existing {
		if !keep[p.PublicKey] {
			target = append(target, wgtypes.PeerConfig{
				PublicKey: p.PublicKey,
				Remove:    true,
			})
		}
	}
	return target
}

func (m *Manager) Peers() ([]wgtypes.Peer, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wgctrl: %w", err)
	}
	defer client.Close()
	dev, err := client.Device(m.iface)
	if err != nil {
		return nil, fmt.Errorf("read wireguard device: %w", err)
	}
	return dev.Peers, nil
}

// ListenPort returns the WireGuard listen port currently in use. If the
// device was configured with ListenPort = 0, this reports the ephemeral
// port the kernel selected. Returns 0 with no error before the device has
// been fully configured.
func (m *Manager) ListenPort() (uint16, error) {
	client, err := wgctrl.New()
	if err != nil {
		return 0, fmt.Errorf("open wgctrl: %w", err)
	}
	defer client.Close()
	dev, err := client.Device(m.iface)
	if err != nil {
		return 0, fmt.Errorf("read wireguard device: %w", err)
	}
	if dev.ListenPort < 0 || dev.ListenPort > 65535 {
		return 0, fmt.Errorf("listen port %d out of range", dev.ListenPort)
	}
	return uint16(dev.ListenPort), nil
}

func (m *Manager) Teardown() error {
	link, err := netlink.LinkByName(m.iface)
	if err != nil {
		return fmt.Errorf("find link: %w", err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete link: %w", err)
	}
	return nil
}
