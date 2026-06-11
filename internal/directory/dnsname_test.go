package directory

import (
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"vpn", "vpn"},
		{"VPN.Home", "vpn.home"},
		{"vpn.", "vpn"},
		{"VPN.HOME.", "vpn.home"},
	}
	for _, tc := range cases {
		if got := NormalizeDomain(tc.in); got != tc.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateLabel(t *testing.T) {
	valid := []string{"a", "alice", "Alice", "nas-2", "0x1f", strings.Repeat("a", 63)}
	for _, name := range valid {
		if err := ValidateLabel(name); err != nil {
			t.Errorf("ValidateLabel(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{
		"",
		"-alice",
		"alice-",
		"my laptop",
		"db_2",
		"a.b",
		"héllo",
		strings.Repeat("a", 64),
	}
	for _, name := range invalid {
		if err := ValidateLabel(name); err == nil {
			t.Errorf("ValidateLabel(%q) = nil, want error", name)
		}
	}
}

func TestValidateDomain(t *testing.T) {
	valid := []string{"vpn", "vpn.home", "internal", "a.b.c", strings.Repeat("a", 63) + ".vpn"}
	for _, d := range valid {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("ValidateDomain(%q) = %v, want nil", d, err)
		}
	}
	invalid := []string{
		"",
		"VPN",          // not normalized
		"vpn.",         // trailing dot survives only un-normalized input
		".vpn",         // empty leading label
		"vpn..home",    // empty middle label
		"my domain",    // space
		"10.42.0.1",    // IP address
		"fd00::1",      // IPv6 address
		"-vpn.home",    // bad label
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63), // >253 total
	}
	for _, d := range invalid {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("ValidateDomain(%q) = nil, want error", d)
		}
	}
}
