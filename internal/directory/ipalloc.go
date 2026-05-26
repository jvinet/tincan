package directory

import (
	"errors"
	"fmt"
	"net/netip"
)

func NextFreeIP(cidr string, taken []string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", fmt.Errorf("parse CIDR: %w", err)
	}
	if !prefix.Addr().Is4() {
		return "", errors.New("only IPv4 tunnel CIDRs are supported")
	}
	prefix = prefix.Masked()
	bits := prefix.Bits()
	if bits < 0 || bits > 32 {
		return "", fmt.Errorf("invalid IPv4 prefix length %d", bits)
	}
	used := map[uint32]struct{}{}
	for _, raw := range taken {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() {
			return "", fmt.Errorf("invalid taken IPv4 address %q", raw)
		}
		used[addrToUint32(addr)] = struct{}{}
	}
	network := addrToUint32(prefix.Addr())
	size := uint64(1) << uint(32-bits)
	first := uint64(network)
	last := uint64(network) + size - 1
	if bits <= 30 {
		first++
		last--
	}
	for n := first; n <= last; n++ {
		if _, ok := used[uint32(n)]; ok {
			continue
		}
		return uint32ToAddr(uint32(n)).String(), nil
	}
	return "", fmt.Errorf("no free IPs in %s", cidr)
}

func addrToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToAddr(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}
