package discovery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	reactiveCooldown  = 5 * time.Second
	reactiveMaxJitter = 200 * time.Millisecond
)

// burstSchedule holds inter-beacon delays for the startup burst: first
// beacon at t=0s, second at t=2s, third at t=5s.
var burstSchedule = []time.Duration{0, 2 * time.Second, 3 * time.Second}

type senderSockets struct {
	v4 *ipv4.PacketConn
	v6 *ipv6.PacketConn
}

func (s *senderSockets) close() {
	if s.v4 != nil {
		_ = s.v4.Close()
	}
	if s.v6 != nil {
		_ = s.v6.Close()
	}
}

func openSenderSockets() (*senderSockets, error) {
	out := &senderSockets{}
	c4, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	out.v4 = ipv4.NewPacketConn(c4)

	c6, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		// IPv6 might be disabled — proceed with IPv4 only.
		slog.Debug("discovery: IPv6 sender socket unavailable", "error", err)
		return out, nil
	}
	out.v6 = ipv6.NewPacketConn(c6)
	return out, nil
}

// startSender launches the sender goroutine. reactCh is the reactive-trigger
// channel populated by the listener; the sender consumes from it with
// rate-limiting + jitter.
func startSender(ctx context.Context, cfg Config, ipv4Addr, ipv6Addr *net.UDPAddr, ifaceFilter string, store *Store, reactCh <-chan struct{}) error {
	socks, err := openSenderSockets()
	if err != nil {
		return err
	}
	go runSender(ctx, cfg, ipv4Addr, ipv6Addr, ifaceFilter, store, socks, reactCh)
	return nil
}

func runSender(ctx context.Context, cfg Config, ipv4Addr, ipv6Addr *net.UDPAddr, ifaceFilter string, store *Store, socks *senderSockets, react <-chan struct{}) {
	defer socks.close()

	for _, delay := range burstSchedule {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			emit(ipv4Addr, ipv6Addr, ifaceFilter, store, socks)
		}
	}

	ticker := time.NewTicker(cfg.BeaconInterval)
	defer ticker.Stop()
	var lastReactive time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			emit(ipv4Addr, ipv6Addr, ifaceFilter, store, socks)
		case <-react:
			if time.Since(lastReactive) < reactiveCooldown {
				continue
			}
			jitter := time.Duration(mrand.Int64N(int64(reactiveMaxJitter)))
			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter):
			}
			emit(ipv4Addr, ipv6Addr, ifaceFilter, store, socks)
			lastReactive = time.Now()
		}
	}
}

func emit(ipv4Addr, ipv6Addr *net.UDPAddr, ifaceFilter string, store *Store, socks *senderSockets) {
	selfPub, selfPort, ready := store.Self()
	if !ready {
		return
	}
	payload, err := Encode(Beacon{
		V:         BeaconSchemaVersion,
		PublicKey: selfPub,
		Port:      selfPort,
		Nonce:     randomNonce(),
	})
	if err != nil {
		slog.Warn("discovery: beacon encode failed", "error", err)
		return
	}
	ifaces, err := liveLANInterfaces(ifaceFilter)
	if err != nil {
		slog.Warn("discovery: interface enumeration failed", "error", err)
		return
	}
	if len(ifaces) == 0 {
		return
	}
	for _, iface := range ifaces {
		sendOne(socks, iface, ipv4Addr, ipv6Addr, payload)
	}
}

func sendOne(socks *senderSockets, iface net.Interface, ipv4Addr, ipv6Addr *net.UDPAddr, payload []byte) {
	if socks.v4 != nil && ipv4Addr != nil {
		if err := socks.v4.SetMulticastInterface(&iface); err != nil {
			slog.Debug("discovery: SetMulticastInterface IPv4 failed", "iface", iface.Name, "error", err)
		} else {
			_ = socks.v4.SetMulticastTTL(1)
			if _, err := socks.v4.WriteTo(payload, nil, ipv4Addr); err != nil {
				slog.Debug("discovery: IPv4 send failed", "iface", iface.Name, "error", err)
			}
		}
	}
	if socks.v6 != nil && ipv6Addr != nil {
		if err := socks.v6.SetMulticastInterface(&iface); err != nil {
			slog.Debug("discovery: SetMulticastInterface IPv6 failed", "iface", iface.Name, "error", err)
		} else {
			_ = socks.v6.SetMulticastHopLimit(1)
			if _, err := socks.v6.WriteTo(payload, nil, ipv6Addr); err != nil {
				slog.Debug("discovery: IPv6 send failed", "iface", iface.Name, "error", err)
			}
		}
	}
}

func randomNonce() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint64(b[:])
}
