//go:build linux

package wg

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func ensureAddress(link netlink.Link, tunnelIP string) error {
	_, want, err := net.ParseCIDR(tunnelIP + "/32")
	if err != nil {
		return fmt.Errorf("parse tunnel address: %w", err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list link addresses: %w", err)
	}
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		if addr.IPNet.String() == want.String() {
			continue
		}
		if ones, bits := addr.IPNet.Mask.Size(); bits == 32 && ones == 32 {
			_ = netlink.AddrDel(link, &addr)
		}
	}
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: want}); err != nil {
		return fmt.Errorf("assign tunnel address: %w", err)
	}
	return nil
}

func ensureRoute(link netlink.Link, cidr string) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse route CIDR: %w", err)
	}
	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Scope: netlink.SCOPE_LINK}
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("ensure route: %w", err)
	}
	return nil
}
