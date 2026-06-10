package discovery

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// startListeners launches the IPv4 and IPv6 multicast listeners. Each
// listener reads beacons, decodes them, filters by directory membership,
// and updates the store. On meaningful updates, it nudges wakeCh so the
// daemon loop reconverges immediately. On a *first-seen* pubkey, it also
// nudges reactCh so the sender can answer with a beacon immediately.
// Alongside each read loop runs a membership maintainer that keeps the
// multicast joins alive as interfaces come, go, and bounce.
func startListeners(ctx context.Context, cfg Config, ipv4Addr, ipv6Addr *net.UDPAddr, ifaces []net.Interface, store *Store, dir DirectorySource, wakeCh chan<- string, reactCh chan<- struct{}) error {
	if ipv4Addr != nil {
		if err := startIPv4Listener(ctx, cfg, ipv4Addr, ifaces, store, dir, wakeCh, reactCh); err != nil {
			return err
		}
	}
	if ipv6Addr != nil {
		if err := startIPv6Listener(ctx, cfg, ipv6Addr, ifaces, store, dir, wakeCh, reactCh); err != nil {
			return err
		}
	}
	return nil
}

func startIPv4Listener(ctx context.Context, cfg Config, addr *net.UDPAddr, ifaces []net.Interface, store *Store, dir DirectorySource, wakeCh chan<- string, reactCh chan<- struct{}) error {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(addr.Port))
	if err != nil {
		return err
	}
	p := ipv4.NewPacketConn(conn)
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		_ = conn.Close()
		return err
	}
	group := &net.UDPAddr{IP: addr.IP}
	if joined := rejoinGroups(p, group, ifaces, "IPv4"); joined == 0 {
		slog.Warn("discovery: no interfaces joined IPv4 multicast", "addr", addr.String())
	} else {
		slog.Debug("discovery: IPv4 multicast listening", "joined", joined, "addr", addr.String())
	}
	go runIPv4Listener(ctx, p, conn, store, dir, wakeCh, reactCh)
	go maintainMembership(ctx, p, group, cfg, "IPv4")
	return nil
}

func startIPv6Listener(ctx context.Context, cfg Config, addr *net.UDPAddr, ifaces []net.Interface, store *Store, dir DirectorySource, wakeCh chan<- string, reactCh chan<- struct{}) error {
	conn, err := net.ListenPacket("udp6", "[::]:"+strconv.Itoa(addr.Port))
	if err != nil {
		return err
	}
	p := ipv6.NewPacketConn(conn)
	if err := p.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		_ = conn.Close()
		return err
	}
	group := &net.UDPAddr{IP: addr.IP}
	if joined := rejoinGroups(p, group, ifaces, "IPv6"); joined == 0 {
		slog.Warn("discovery: no interfaces joined IPv6 multicast", "addr", addr.String())
	} else {
		slog.Debug("discovery: IPv6 multicast listening", "joined", joined, "addr", addr.String())
	}
	go runIPv6Listener(ctx, p, conn, store, dir, wakeCh, reactCh)
	go maintainMembership(ctx, p, group, cfg, "IPv6")
	return nil
}

// groupConn is the multicast-membership subset of ipv4.PacketConn and
// ipv6.PacketConn, factored out so membership maintenance is testable
// with a fake.
type groupConn interface {
	JoinGroup(*net.Interface, net.Addr) error
	LeaveGroup(*net.Interface, net.Addr) error
}

// maintainMembership periodically re-enumerates LAN interfaces and
// re-joins the multicast group on each, paced by the beacon interval.
// Without it, membership is frozen at whatever interfaces existed when
// the daemon started: a daemon that wins the boot race against DHCP or
// Wi-Fi association stays receive-deaf for its entire lifetime while
// still transmitting beacons (the sender re-enumerates per emit), and a
// snooping switch that ages the group out of its tables silences
// reception with no local event to react to. Runs until ctx is canceled.
func maintainMembership(ctx context.Context, conn groupConn, group net.Addr, cfg Config, family string) {
	interval := cfg.BeaconInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		ifaces, err := liveLANInterfaces(cfg.InterfaceFilter)
		if err != nil {
			slog.Debug("discovery: interface enumeration failed during re-join", "error", err)
			continue
		}
		rejoinGroups(conn, group, ifaces, family)
	}
}

// rejoinGroups joins group on every given interface, leaving first so the
// join is never a refcount no-op: the fresh join makes the kernel emit a
// new IGMP/MLD membership report, which restores forwarding on snooping
// switches that aged the group out (common on LANs with no IGMP querier).
// Leave errors are expected (the group may not be joined on that
// interface yet) and ignored; join failures are logged and skipped.
// Returns the number of successful joins.
func rejoinGroups(conn groupConn, group net.Addr, ifaces []net.Interface, family string) int {
	joined := 0
	for i := range ifaces {
		_ = conn.LeaveGroup(&ifaces[i], group)
		if err := conn.JoinGroup(&ifaces[i], group); err != nil {
			slog.Debug("discovery: multicast join failed", "family", family, "iface", ifaces[i].Name, "error", err)
			continue
		}
		joined++
	}
	return joined
}

func runIPv4Listener(ctx context.Context, p *ipv4.PacketConn, conn net.PacketConn, store *Store, dir DirectorySource, wakeCh chan<- string, reactCh chan<- struct{}) {
	defer conn.Close()
	buf := make([]byte, 1500)
	go func() {
		<-ctx.Done()
		_ = conn.SetReadDeadline(time.Unix(0, 0))
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			if netTimedOut(err) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			slog.Debug("discovery: IPv4 read failed", "error", err)
			continue
		}
		processBeacon(buf[:n], src, ifaceIndex(cm), store, dir, wakeCh, reactCh)
	}
}

func runIPv6Listener(ctx context.Context, p *ipv6.PacketConn, conn net.PacketConn, store *Store, dir DirectorySource, wakeCh chan<- string, reactCh chan<- struct{}) {
	defer conn.Close()
	buf := make([]byte, 1500)
	go func() {
		<-ctx.Done()
		_ = conn.SetReadDeadline(time.Unix(0, 0))
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			if netTimedOut(err) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			slog.Debug("discovery: IPv6 read failed", "error", err)
			continue
		}
		processBeacon(buf[:n], src, ifaceIndexV6(cm), store, dir, wakeCh, reactCh)
	}
}

func processBeacon(data []byte, src net.Addr, ingressIfIndex int, store *Store, dir DirectorySource, wakeCh chan<- string, reactCh chan<- struct{}) {
	udpSrc, ok := src.(*net.UDPAddr)
	if !ok {
		return
	}
	srcIP := udpSrc.IP
	if srcIP == nil {
		return
	}
	if isLocalIP(srcIP) {
		return
	}
	if srcIP.To4() == nil && srcIP.IsLinkLocalUnicast() {
		// IPv6 link-local source — WG's Endpoint can't use it without a zone
		// ID, and the same peer is almost certainly reachable via a global
		// address that will arrive in a separate beacon. Drop.
		return
	}
	beacon, err := Decode(data)
	if err != nil {
		slog.Debug("discovery: malformed beacon", "src", udpSrc.String(), "error", err)
		return
	}
	currentDir := dir()
	if !isKnownPubkey(currentDir, beacon.PublicKey) {
		return
	}
	selfPub, _, _ := store.Self()
	if beacon.PublicKey == selfPub {
		return
	}
	endpoint := net.JoinHostPort(srcIP.String(), strconv.Itoa(int(beacon.Port)))
	result := store.Update(beacon.PublicKey, endpoint, time.Now())
	slog.Debug("discovery: beacon received",
		"peer_pubkey", beacon.PublicKey,
		"endpoint", endpoint,
		"if_index", ingressIfIndex,
		"changed", result.Changed,
		"first_seen", result.FirstSeen,
	)
	if result.Changed && wakeCh != nil {
		select {
		case wakeCh <- "lan endpoint learned":
		default:
		}
	}
	if result.FirstSeen && reactCh != nil {
		select {
		case reactCh <- struct{}{}:
		default:
		}
	}
}

func isKnownPubkey(dir directory.Directory, pubkey string) bool {
	for i := range dir.Nodes {
		if dir.Nodes[i].PublicKey == pubkey {
			return true
		}
	}
	return false
}

func ifaceIndex(cm *ipv4.ControlMessage) int {
	if cm == nil {
		return 0
	}
	return cm.IfIndex
}

func ifaceIndexV6(cm *ipv6.ControlMessage) int {
	if cm == nil {
		return 0
	}
	return cm.IfIndex
}

func netTimedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
