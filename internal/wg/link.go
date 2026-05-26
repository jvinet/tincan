//go:build linux

package wg

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func (m *Manager) ensureLink() (netlink.Link, error) {
	link, err := netlink.LinkByName(m.iface)
	if err == nil {
		return link, nil
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = m.iface
	attrs.MTU = m.mtu
	link = &netlink.GenericLink{LinkAttrs: attrs, LinkType: "wireguard"}
	if err := netlink.LinkAdd(link); err != nil {
		return nil, fmt.Errorf("create WireGuard link %q: %w", m.iface, err)
	}
	link, err = netlink.LinkByName(m.iface)
	if err != nil {
		return nil, fmt.Errorf("find created WireGuard link %q: %w", m.iface, err)
	}
	return link, nil
}
