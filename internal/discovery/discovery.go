// Package discovery implements LAN peer discovery for Tincan via UDP
// multicast beacons. Two NAT'd peers behind the same router publish their
// pubkey + WireGuard listen port on a well-known multicast group; the
// receiving daemon pairs the beacon's source IP with the announced port
// to produce a candidate LAN endpoint, which the WireGuard layer can then
// use in preference to the relay path.
//
// Discovery has no admin/server component — it's purely client-to-client
// on the local LAN — and authentication is implicit: a beacon claims a
// pubkey but doesn't prove possession; the downstream WireGuard handshake
// either completes (proving the claim) or doesn't (causing the existing
// relay state machine to fall back). See spec/lan-discovery.md.
package discovery

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jvinet/tincan/internal/directory"
)

// Config holds the runtime parameters governing the discovery system.
type Config struct {
	// MulticastIPv4 is the IPv4 multicast group address, e.g. "239.255.84.67:51821".
	MulticastIPv4 string
	// MulticastIPv6 is the IPv6 multicast group address, e.g. "[ff02::1:8443]:51821".
	MulticastIPv6 string
	// BeaconInterval is the steady-state cadence between outbound beacons.
	// It also paces the listeners' multicast membership maintenance (see
	// maintainMembership).
	BeaconInterval time.Duration
	// BeaconTTL is how long a learned LAN endpoint remains usable without
	// a refresh beacon. Should be at least 2× BeaconInterval.
	BeaconTTL time.Duration
	// InterfaceFilter is the name of an interface to exclude from beacon
	// egress/ingress filtering — typically the Tincan WireGuard interface.
	InterfaceFilter string
}

// DirectorySource is a closure yielding the most recent directory. The
// listener consults it to filter beacons whose claimed pubkey isn't a
// recognized peer.
type DirectorySource func() directory.Directory

// Start launches the sender and listener goroutines and returns a Store
// exposing the learned LAN endpoints. The goroutines run until ctx is
// canceled. wakeCh is signaled (best-effort) whenever the store changes;
// the daemon loop uses this to reconverge immediately rather than waiting
// for the next sync tick.
func Start(ctx context.Context, cfg Config, dir DirectorySource, wakeCh chan<- string) (*Store, error) {
	ipv4Addr, err := net.ResolveUDPAddr("udp4", cfg.MulticastIPv4)
	if err != nil {
		return nil, fmt.Errorf("resolve IPv4 multicast: %w", err)
	}
	ipv6Addr, err := net.ResolveUDPAddr("udp6", cfg.MulticastIPv6)
	if err != nil {
		return nil, fmt.Errorf("resolve IPv6 multicast: %w", err)
	}

	store := NewStore(cfg.BeaconTTL)

	ifaces, err := liveLANInterfaces(cfg.InterfaceFilter)
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	// Goroutines spawned below run on this derived context. If a later start
	// step fails, cancel it so already-spawned listeners don't leak as live
	// sockets feeding a store nobody reads. On success the context lives
	// until the caller's ctx is canceled.
	runCtx, cancel := context.WithCancel(ctx)
	started := false
	defer func() {
		if !started {
			cancel()
		}
	}()

	reactCh := make(chan struct{}, 1)
	if err := startListeners(runCtx, cfg, ipv4Addr, ipv6Addr, ifaces, store, dir, wakeCh, reactCh); err != nil {
		return nil, fmt.Errorf("start listeners: %w", err)
	}
	if err := startSender(runCtx, cfg, ipv4Addr, ipv6Addr, cfg.InterfaceFilter, store, reactCh); err != nil {
		return nil, fmt.Errorf("start sender: %w", err)
	}
	started = true
	return store, nil
}
