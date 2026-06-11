//go:build linux

package wg

import (
	"fmt"
	"time"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"github.com/jvinet/tincan/internal/relay"
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

// Apply reconciles the WireGuard device against the directory. It returns
// the base64 public keys of peers whose endpoint was pushed from
// configuration by this call — as opposed to endpoints the kernel learned
// from the wire, which preserveLiveEndpoints left alone. The admin's
// endpoint observation uses this to refuse to republish an endpoint that
// no handshake has validated yet (see admin.MergeObservations). The pushed
// list is valid even when Apply returns an error, as long as the
// ConfigureDevice call itself succeeded.
func (m *Manager) Apply(self directory.Node, dir directory.Directory, relayed map[string]bool, lanLookup LANEndpointLookup) ([]string, error) {
	link, err := netlink.LinkByName(m.iface)
	if err != nil {
		return nil, fmt.Errorf("find link %q: %w", m.iface, err)
	}
	peers, err := BuildPeerConfigs(m.wg, self, dir, relayed, lanLookup)
	if err != nil {
		return nil, err
	}
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wgctrl: %w", err)
	}
	defer client.Close()
	peers = mergeAgainstKernel(client, m.iface, peers)
	if err := client.ConfigureDevice(m.iface, wgtypes.Config{
		PrivateKey:   &m.privateKey,
		ListenPort:   m.listenPort,
		ReplacePeers: false,
		Peers:        peers,
	}); err != nil {
		return nil, fmt.Errorf("configure WireGuard device: %w", err)
	}
	pushed := pushedEndpointKeys(peers)
	if err := ensureAddress(link, self.TunnelIP); err != nil {
		return pushed, err
	}
	if err := ensureRoute(link, dir.NetworkCIDR); err != nil {
		return pushed, err
	}
	return pushed, nil
}

// pushedEndpointKeys lists the peers whose PeerConfig still carries an
// Endpoint after mergeAgainstKernel — exactly the set whose kernel endpoint
// the ConfigureDevice call overwrote from configuration.
func pushedEndpointKeys(peers []wgtypes.PeerConfig) []string {
	var pushed []string
	for i := range peers {
		if peers[i].Remove || peers[i].Endpoint == nil {
			continue
		}
		pushed = append(pushed, peers[i].PublicKey.String())
	}
	return pushed
}

func (m *Manager) Ensure(self directory.Node, dir directory.Directory, relayed map[string]bool) error {
	if err := m.Up(); err != nil {
		return err
	}
	_, err := m.Apply(self, dir, relayed, nil)
	return err
}

// mergeAgainstKernel adapts a freshly-built peer list for use with
// ReplacePeers=false: it normalizes nil keepalive durations to an explicit
// zero (so the kernel reliably picks up role changes), drops endpoint
// overrides for peers whose current path is proven live (see
// preserveLiveEndpoints), and appends Remove entries for any peer currently
// in the kernel that no longer appears in the directory. Using
// ReplacePeers=false preserves kernel-tracked state (LastHandshakeTime,
// roamed endpoints) across reconcile loops, which the admin's endpoint
// observation and the relay controller's liveness checks depend on.
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
	peers = preserveLiveEndpoints(peers, dev.Peers, time.Now())
	return appendDeletions(peers, dev.Peers)
}

// handshakeFreshWindow is relay.DefaultDirectFailedAfter: while a kernel
// peer's last handshake is younger than this, its current path works and
// its endpoint is left alone; once older, the relay controller considers
// the path dead and Apply resumes pushing endpoint picks. The two must
// agree, or Apply would overwrite endpoints the controller still trusts.
const handshakeFreshWindow = relay.DefaultDirectFailedAfter

// preserveLiveEndpoints clears the Endpoint on any PeerConfig whose kernel
// peer completed a handshake within handshakeFreshWindow. A fresh handshake
// proves the kernel's current endpoint works — and it may be one the kernel
// roamed to (e.g. a same-LAN source address) that never appears in the
// directory or LAN store. Overwriting it would blackhole traffic to that
// peer until its next inbound packet re-roams the endpoint. Endpoints are
// only pushed when the path is already stale or the peer is new, when
// changing them can't make things worse.
func preserveLiveEndpoints(peers []wgtypes.PeerConfig, kernel []wgtypes.Peer, now time.Time) []wgtypes.PeerConfig {
	byKey := make(map[wgtypes.Key]wgtypes.Peer, len(kernel))
	for _, kp := range kernel {
		byKey[kp.PublicKey] = kp
	}
	for i := range peers {
		if peers[i].Endpoint == nil {
			continue
		}
		kp, ok := byKey[peers[i].PublicKey]
		if !ok || kp.LastHandshakeTime.IsZero() {
			continue
		}
		if now.Sub(kp.LastHandshakeTime) < handshakeFreshWindow {
			peers[i].Endpoint = nil
		}
	}
	return peers
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
