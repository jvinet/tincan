//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/relay"
	"github.com/vishvananda/netlink"
)

// startNetworkWatcher launches a goroutine that watches the kernel for IP
// address changes on non-loopback, non-tincan interfaces. On any such
// change, it tells the relay controller to probe direct connectivity again
// (e.g. because the laptop just switched wifi networks) and wakes the
// daemon's main loop so reconciliation runs immediately rather than waiting
// for the next interval.
//
// IPv6 SLAAC lifetime renewals and DHCP refreshes both surface as RTM_NEWADDR
// events for an address that already exists; without dedup, a typical
// hosting-provider VM emits these every few minutes and turns every relayed
// peer into a constant DIRECT-probe loop. We track the address set ourselves
// and only signal on actual add/remove transitions.
func startNetworkWatcher(ctx context.Context, configPath string, controller *relay.Controller, wakeCh chan<- string, perr *printer) {
	iface := config.DefaultInterface
	if cfg, err := config.Load(configPath); err == nil && cfg.Wireguard.Interface != "" {
		iface = cfg.Wireguard.Interface
	}
	tracker := newAddrTracker(iface)
	tracker.prime()
	go func() {
		updates := make(chan netlink.AddrUpdate)
		done := make(chan struct{})
		defer close(done)
		if err := netlink.AddrSubscribeWithOptions(updates, done, netlink.AddrSubscribeOptions{}); err != nil {
			perr.fail("netlink subscribe failed; relay probe on network change disabled: %v", err)
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case update, ok := <-updates:
				if !ok {
					if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
						perr.fail("netlink updates channel closed: %v", err)
					}
					return
				}
				if !tracker.observe(update) {
					continue
				}
				controller.MarkNetChanged()
				select {
				case wakeCh <- "local network changed":
				default:
				}
			}
		}
	}()
}

// addrTracker dedupes netlink address events. The kernel re-emits RTM_NEWADDR
// for lifetime renewals (IPv6 RA, DHCP renew), but those don't represent a
// change in what addresses are configured. We maintain the current set
// ourselves and only report when an address actually appears or disappears.
type addrTracker struct {
	ourIface string

	mu   sync.Mutex
	seen map[string]struct{} // "linkindex|ipnet"
}

func newAddrTracker(ourIface string) *addrTracker {
	return &addrTracker{ourIface: ourIface, seen: map[string]struct{}{}}
}

// prime seeds the tracker with currently-configured addresses so the kernel's
// initial NEWADDR events for already-existing addresses don't fire spurious
// wakes at startup.
func (t *addrTracker) prime() {
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, link := range links {
		if t.skipLink(link.Attrs().Name) {
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IPNet == nil {
				continue
			}
			t.seen[addrKey(link.Attrs().Index, *a.IPNet)] = struct{}{}
		}
	}
}

// observe processes a netlink AddrUpdate and returns true iff it represents a
// real transition (a new address gained or an old address lost). Lifetime
// renewals and events on filtered interfaces return false.
func (t *addrTracker) observe(update netlink.AddrUpdate) bool {
	link, err := netlink.LinkByIndex(update.LinkIndex)
	if err != nil {
		return false
	}
	if t.skipLink(link.Attrs().Name) {
		return false
	}
	return t.observeKey(addrKey(update.LinkIndex, update.LinkAddress), update.NewAddr)
}

// observeKey is the lockable state transition: returns true on transitions
// (add to set / remove from set), false on duplicates. Split out for testing
// without requiring a real netlink interface.
func (t *addrTracker) observeKey(key string, isNew bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if isNew {
		if _, ok := t.seen[key]; ok {
			return false
		}
		t.seen[key] = struct{}{}
		return true
	}
	if _, ok := t.seen[key]; !ok {
		return false
	}
	delete(t.seen, key)
	return true
}

func (t *addrTracker) skipLink(name string) bool {
	return name == "lo" || name == t.ourIface
}

func addrKey(linkIdx int, ipnet net.IPNet) string {
	return fmt.Sprintf("%d|%s", linkIdx, ipnet.String())
}
