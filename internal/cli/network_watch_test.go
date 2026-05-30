//go:build linux

package cli

import (
	"net"
	"testing"
)

func TestAddrTrackerObserveKey(t *testing.T) {
	tr := newAddrTracker("tincan0")
	_, ipnet, _ := net.ParseCIDR("2001:db8::1/64")
	key := addrKey(42, *ipnet)

	if !tr.observeKey(key, true) {
		t.Fatal("first NEWADDR should fire")
	}
	if tr.observeKey(key, true) {
		t.Fatal("repeat NEWADDR (SLAAC renewal) should be deduped")
	}
	if tr.observeKey(key, true) {
		t.Fatal("third NEWADDR should still be deduped")
	}
	if !tr.observeKey(key, false) {
		t.Fatal("DELADDR for a tracked address should fire")
	}
	if tr.observeKey(key, false) {
		t.Fatal("DELADDR for an untracked address should not fire")
	}
	if !tr.observeKey(key, true) {
		t.Fatal("NEWADDR after deletion should fire again")
	}
}

func TestAddrTrackerKeysAreStable(t *testing.T) {
	_, a, _ := net.ParseCIDR("192.0.2.1/24")
	_, b, _ := net.ParseCIDR("192.0.2.1/24")
	if addrKey(7, *a) != addrKey(7, *b) {
		t.Fatal("equivalent IPNets should produce equal keys")
	}
	if addrKey(7, *a) == addrKey(8, *a) {
		t.Fatal("same address on different links should produce different keys")
	}
}

func TestAddrTrackerSkipsFilteredInterfaces(t *testing.T) {
	tr := newAddrTracker("tincan0")
	if !tr.skipLink("lo") {
		t.Error("lo should be filtered")
	}
	if !tr.skipLink("tincan0") {
		t.Error("our wg iface should be filtered")
	}
	if tr.skipLink("eth0") {
		t.Error("eth0 should not be filtered")
	}
}
