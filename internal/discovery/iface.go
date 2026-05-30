package discovery

import (
	"net"
)

// liveLANInterfaces returns the set of kernel interfaces eligible for
// multicast beacon traffic. An interface qualifies when all of:
//   - not loopback
//   - name does not match skip (typically the tincan interface)
//   - operationally up
//   - has at least one non-link-local global-scope IPv4 or IPv6 address
func liveLANInterfaces(skip string) ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]net.Interface, 0, len(all))
	for _, iface := range all {
		if shouldUseInterface(iface, skip) {
			out = append(out, iface)
		}
	}
	return out, nil
}

func shouldUseInterface(iface net.Interface, skip string) bool {
	if iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	if iface.Name == skip {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if hasGlobalScope(ipnet.IP) {
			return true
		}
	}
	return false
}

func hasGlobalScope(ip net.IP) bool {
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

// isLocalIP returns true if the given IP is configured on any local
// interface. Used by the listener to drop beacons echoed back to us via
// multicast loopback.
func isLocalIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.Equal(ip) {
			return true
		}
	}
	return false
}
