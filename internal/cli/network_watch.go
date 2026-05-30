//go:build linux

package cli

import (
	"context"
	"errors"

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
func startNetworkWatcher(ctx context.Context, configPath string, controller *relay.Controller, wakeCh chan<- string, perr *printer) {
	iface := config.DefaultInterface
	if cfg, err := config.Load(configPath); err == nil && cfg.Wireguard.Interface != "" {
		iface = cfg.Wireguard.Interface
	}
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
				if !networkChangeRelevant(update, iface) {
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

// networkChangeRelevant filters out changes on loopback and on our own
// WireGuard interface (those are caused by us, not by external network
// events). Failure to resolve the link is treated as "not relevant" —
// safer than waking the daemon for noise.
func networkChangeRelevant(update netlink.AddrUpdate, ourIface string) bool {
	link, err := netlink.LinkByIndex(update.LinkIndex)
	if err != nil {
		return false
	}
	name := link.Attrs().Name
	if name == "lo" || name == ourIface {
		return false
	}
	return true
}
