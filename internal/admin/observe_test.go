package admin

import (
	"net"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustWGPub(t *testing.T) (priv, pub string) {
	t.Helper()
	p, k, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}

func wgKey(t *testing.T, pub string) wgtypes.Key {
	t.Helper()
	k, err := keys.ParseWGPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func udp(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestMergeObservationsFirstObservationSets(t *testing.T) {
	_, bobPub := mustWGPub(t)
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2"},
	}}
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	peers := []wgtypes.Peer{{
		PublicKey:         wgKey(t, bobPub),
		Endpoint:          udp(t, "203.0.113.7:41234"),
		LastHandshakeTime: now.Add(-30 * time.Second),
	}}

	out, changed := MergeObservations(dir, peers, now, 0, 0)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if out.Nodes[0].ObservedEndpoint != "203.0.113.7:41234" {
		t.Fatalf("ObservedEndpoint=%q", out.Nodes[0].ObservedEndpoint)
	}
	if !out.Nodes[0].ObservedAt.Equal(now) {
		t.Fatalf("ObservedAt=%v want %v", out.Nodes[0].ObservedAt, now)
	}
}

func TestMergeObservationsNoopWhenUnchangedAndFresh(t *testing.T) {
	_, bobPub := mustWGPub(t)
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	previousObservation := now.Add(-5 * time.Minute) // within refreshInterval
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2", ObservedEndpoint: "203.0.113.7:41234", ObservedAt: previousObservation},
	}}
	peers := []wgtypes.Peer{{
		PublicKey:         wgKey(t, bobPub),
		Endpoint:          udp(t, "203.0.113.7:41234"),
		LastHandshakeTime: now.Add(-30 * time.Second),
	}}

	out, changed := MergeObservations(dir, peers, now, 0, 0)
	if changed {
		t.Fatal("expected changed=false when endpoint matches and oat is fresh")
	}
	if !out.Nodes[0].ObservedAt.Equal(previousObservation) {
		t.Fatalf("ObservedAt should not have been refreshed, got %v", out.Nodes[0].ObservedAt)
	}
}

func TestMergeObservationsRefreshesAfterRefreshInterval(t *testing.T) {
	_, bobPub := mustWGPub(t)
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	previousObservation := now.Add(-DefaultRefreshInterval - time.Minute)
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2", ObservedEndpoint: "203.0.113.7:41234", ObservedAt: previousObservation},
	}}
	peers := []wgtypes.Peer{{
		PublicKey:         wgKey(t, bobPub),
		Endpoint:          udp(t, "203.0.113.7:41234"),
		LastHandshakeTime: now.Add(-30 * time.Second),
	}}

	out, changed := MergeObservations(dir, peers, now, 0, 0)
	if !changed {
		t.Fatal("expected changed=true after refreshInterval elapsed")
	}
	if !out.Nodes[0].ObservedAt.Equal(now) {
		t.Fatalf("ObservedAt=%v want refresh to %v", out.Nodes[0].ObservedAt, now)
	}
}

func TestMergeObservationsUpdatesWhenEndpointChanges(t *testing.T) {
	_, bobPub := mustWGPub(t)
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2", ObservedEndpoint: "203.0.113.7:41234", ObservedAt: now.Add(-time.Minute)},
	}}
	peers := []wgtypes.Peer{{
		PublicKey:         wgKey(t, bobPub),
		Endpoint:          udp(t, "203.0.113.7:55555"),
		LastHandshakeTime: now.Add(-30 * time.Second),
	}}

	out, changed := MergeObservations(dir, peers, now, 0, 0)
	if !changed {
		t.Fatal("expected changed=true when endpoint string differs")
	}
	if out.Nodes[0].ObservedEndpoint != "203.0.113.7:55555" {
		t.Fatalf("ObservedEndpoint=%q", out.Nodes[0].ObservedEndpoint)
	}
	if !out.Nodes[0].ObservedAt.Equal(now) {
		t.Fatalf("ObservedAt=%v want %v", out.Nodes[0].ObservedAt, now)
	}
}

func TestMergeObservationsClearsWhenHandshakeStale(t *testing.T) {
	_, bobPub := mustWGPub(t)
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2", ObservedEndpoint: "203.0.113.7:41234", ObservedAt: now.Add(-time.Minute)},
	}}
	peers := []wgtypes.Peer{{
		PublicKey:         wgKey(t, bobPub),
		Endpoint:          udp(t, "203.0.113.7:41234"),
		LastHandshakeTime: now.Add(-DefaultHandshakeFresh - time.Minute),
	}}

	out, changed := MergeObservations(dir, peers, now, 0, 0)
	if !changed {
		t.Fatal("expected changed=true when handshake stale and prior observation existed")
	}
	if out.Nodes[0].ObservedEndpoint != "" {
		t.Fatalf("ObservedEndpoint=%q want cleared", out.Nodes[0].ObservedEndpoint)
	}
	if !out.Nodes[0].ObservedAt.IsZero() {
		t.Fatalf("ObservedAt=%v want zero", out.Nodes[0].ObservedAt)
	}
}

func TestMergeObservationsClearsWhenPeerAbsent(t *testing.T) {
	_, bobPub := mustWGPub(t)
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2", ObservedEndpoint: "203.0.113.7:41234", ObservedAt: now.Add(-time.Minute)},
	}}

	out, changed := MergeObservations(dir, nil, now, 0, 0)
	if !changed {
		t.Fatal("expected changed=true when peer absent from wgctrl and prior observation existed")
	}
	if out.Nodes[0].ObservedEndpoint != "" || !out.Nodes[0].ObservedAt.IsZero() {
		t.Fatalf("node not cleared: %+v", out.Nodes[0])
	}
}

func TestMergeObservationsNoopWhenAlreadyCleared(t *testing.T) {
	_, bobPub := mustWGPub(t)
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2"},
	}}

	_, changed := MergeObservations(dir, nil, now, 0, 0)
	if changed {
		t.Fatal("expected changed=false when nothing to clear")
	}
}

func TestMergeObservationsSkipsNodeWithOperatorEndpoint(t *testing.T) {
	_, alicePub := mustWGPub(t)
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "alice", PublicKey: alicePub, TunnelIP: "10.42.0.1", Endpoint: "alice.example.com:51820"},
	}}
	peers := []wgtypes.Peer{{
		PublicKey:         wgKey(t, alicePub),
		Endpoint:          udp(t, "203.0.113.7:41234"),
		LastHandshakeTime: now.Add(-30 * time.Second),
	}}

	out, changed := MergeObservations(dir, peers, now, 0, 0)
	if changed {
		t.Fatal("expected changed=false for node with operator Endpoint")
	}
	if out.Nodes[0].ObservedEndpoint != "" || !out.Nodes[0].ObservedAt.IsZero() {
		t.Fatalf("operator-configured node was touched: %+v", out.Nodes[0])
	}
}

func TestMergeObservationsMixed(t *testing.T) {
	_, alicePub := mustWGPub(t)
	_, bobPub := mustWGPub(t)
	_, carolPub := mustWGPub(t)
	_, daniPub := mustWGPub(t)
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	dir := directory.Directory{Nodes: []directory.Node{
		// alice: operator endpoint, must be untouched
		{Name: "alice", PublicKey: alicePub, TunnelIP: "10.42.0.1", Endpoint: "alice.example.com:51820"},
		// bob: no prior observation, fresh handshake → set
		{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2"},
		// carol: prior observation, stale handshake → clear
		{Name: "carol", PublicKey: carolPub, TunnelIP: "10.42.0.3", ObservedEndpoint: "198.51.100.5:6000", ObservedAt: now.Add(-time.Hour)},
		// dani: no prior, no peer entry → no-op
		{Name: "dani", PublicKey: daniPub, TunnelIP: "10.42.0.4"},
	}}
	peers := []wgtypes.Peer{
		{PublicKey: wgKey(t, alicePub), Endpoint: udp(t, "203.0.113.1:51820"), LastHandshakeTime: now.Add(-time.Minute)},
		{PublicKey: wgKey(t, bobPub), Endpoint: udp(t, "203.0.113.2:5000"), LastHandshakeTime: now.Add(-time.Minute)},
		{PublicKey: wgKey(t, carolPub), Endpoint: udp(t, "203.0.113.3:6000"), LastHandshakeTime: now.Add(-time.Hour)},
	}

	out, changed := MergeObservations(dir, peers, now, 0, 0)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if out.Nodes[0].ObservedEndpoint != "" {
		t.Fatalf("alice was touched: %+v", out.Nodes[0])
	}
	if out.Nodes[1].ObservedEndpoint != "203.0.113.2:5000" || !out.Nodes[1].ObservedAt.Equal(now) {
		t.Fatalf("bob not observed correctly: %+v", out.Nodes[1])
	}
	if out.Nodes[2].ObservedEndpoint != "" || !out.Nodes[2].ObservedAt.IsZero() {
		t.Fatalf("carol not cleared: %+v", out.Nodes[2])
	}
	if out.Nodes[3].ObservedEndpoint != "" || !out.Nodes[3].ObservedAt.IsZero() {
		t.Fatalf("dani should be unchanged: %+v", out.Nodes[3])
	}
}

func TestMergeObservationsDoesNotMutateInput(t *testing.T) {
	_, bobPub := mustWGPub(t)
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2"},
	}}
	peers := []wgtypes.Peer{{
		PublicKey:         wgKey(t, bobPub),
		Endpoint:          udp(t, "203.0.113.7:41234"),
		LastHandshakeTime: now.Add(-30 * time.Second),
	}}

	_, _ = MergeObservations(dir, peers, now, 0, 0)
	if dir.Nodes[0].ObservedEndpoint != "" {
		t.Fatalf("input directory was mutated: %+v", dir.Nodes[0])
	}
}
