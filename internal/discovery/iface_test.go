package discovery

import (
	"net"
	"testing"
)

func TestHasGlobalScope(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"public IPv4", "8.8.8.8", true},
		{"private IPv4", "192.168.1.5", true},
		{"link-local IPv4", "169.254.1.1", false},
		{"loopback IPv4", "127.0.0.1", false},
		{"unspecified", "0.0.0.0", false},
		{"IPv6 ULA", "fc00::1", true},
		{"IPv6 link-local", "fe80::1", false},
		{"IPv6 loopback", "::1", false},
		{"IPv6 global", "2001:db8::1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("parse %q", tc.ip)
			}
			if got := hasGlobalScope(ip); got != tc.want {
				t.Fatalf("hasGlobalScope(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}
