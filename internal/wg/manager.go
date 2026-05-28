//go:build linux

package wg

import (
	"fmt"

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

func (m *Manager) Apply(self directory.Node, dir directory.Directory) error {
	link, err := netlink.LinkByName(m.iface)
	if err != nil {
		return fmt.Errorf("find link %q: %w", m.iface, err)
	}
	peers, err := BuildPeerConfigs(m.wg, self, dir)
	if err != nil {
		return err
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wgctrl: %w", err)
	}
	defer client.Close()
	if err := client.ConfigureDevice(m.iface, wgtypes.Config{
		PrivateKey:   &m.privateKey,
		ListenPort:   m.listenPort,
		ReplacePeers: true,
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

func (m *Manager) Ensure(self directory.Node, dir directory.Directory) error {
	if err := m.Up(); err != nil {
		return err
	}
	return m.Apply(self, dir)
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
