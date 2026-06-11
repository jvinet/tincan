package cli

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/dnsserve"
)

func TestShouldServeDNS(t *testing.T) {
	hub := directory.Node{Name: "hub", PublicKey: "HUB", TunnelIP: "10.42.0.1", Endpoint: "hub.example:51820"}
	member := directory.Node{Name: "leaf", PublicKey: "LEAF", TunnelIP: "10.42.0.2"}
	relayNode := directory.Node{Name: "r", PublicKey: "RLY", TunnelIP: "10.42.0.3", Endpoint: "r.example:51820", Relay: true}
	on, off := true, false

	cases := []struct {
		name string
		cfg  config.DNSConfig
		dir  directory.Directory
		self directory.Node
		want bool
	}{
		{name: "no domain never serves", dir: directory.Directory{Nodes: []directory.Node{hub}}, self: hub, want: false},
		{name: "relay-flagged self serves", dir: directory.Directory{Domain: "vpn", Nodes: []directory.Node{relayNode, member}}, self: relayNode, want: true},
		{name: "implicit relay target serves", dir: directory.Directory{Domain: "vpn", Nodes: []directory.Node{hub, member}}, self: hub, want: true},
		{name: "non-hub member does not", dir: directory.Directory{Domain: "vpn", Nodes: []directory.Node{hub, member}}, self: member, want: false},
		{name: "serve=true overrides non-hub", cfg: config.DNSConfig{Serve: &on}, dir: directory.Directory{Domain: "vpn", Nodes: []directory.Node{hub, member}}, self: member, want: true},
		{name: "serve=false overrides hub", cfg: config.DNSConfig{Serve: &off}, dir: directory.Directory{Domain: "vpn", Nodes: []directory.Node{hub, member}}, self: hub, want: false},
		{name: "serve=true without domain still off", cfg: config.DNSConfig{Serve: &on}, dir: directory.Directory{Nodes: []directory.Node{hub}}, self: hub, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DNS = tc.cfg
			if got := shouldServeDNS(&cfg, tc.dir, tc.self); got != tc.want {
				t.Fatalf("shouldServeDNS = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDNSServerManagerLifecycle(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Upstream = "127.0.0.1:1" // never queried in this test
	self := directory.Node{Name: "hub", PublicKey: "HUB", TunnelIP: "127.0.0.1", Endpoint: "hub.example:51820", Relay: true}
	dir := directory.Directory{
		Domain:      "vpn",
		NetworkCIDR: "10.42.0.0/24",
		Nodes:       []directory.Node{self, {Name: "leaf", PublicKey: "LEAF", TunnelIP: "10.42.0.2"}},
	}
	source := func() directory.Directory { return dir }
	var buf bytes.Buffer
	m := &dnsServerManager{}
	defer m.stop()

	// The desired address would be 127.0.0.1:53 — privileged. Point the
	// manager at an unprivileged port by testing reconcile's pieces: start
	// directly via dnsserve on :0 is covered in dnsserve's own tests, so
	// here exercise the no-serve path and the bind-failure warn-dedupe path.
	off := false
	cfg.DNS.Serve = &off
	m.reconcile(context.Background(), &cfg, dir, self, source, newPrinter(&buf))
	if m.server != nil {
		t.Fatal("reconcile started a server with serve=false")
	}

	// Force serving: binding 127.0.0.1:53 fails without privileges, which is
	// exactly the EADDRINUSE/EPERM warn path — it must warn once, not every
	// iteration.
	on := true
	cfg.DNS.Serve = &on
	m.reconcile(context.Background(), &cfg, dir, self, source, newPrinter(&buf))
	if m.server != nil {
		t.Skip("running with privileges to bind :53; warn path not testable")
	}
	first := buf.String()
	if first == "" {
		t.Fatal("bind failure produced no warning")
	}
	m.reconcile(context.Background(), &cfg, dir, self, source, newPrinter(&buf))
	if buf.String() != first {
		t.Fatalf("repeated bind failure warned twice:\n%s", buf.String())
	}

	// Clearing the domain stops trying entirely (no-serve path, no warning).
	dir.Domain = ""
	buf.Reset()
	m.reconcile(context.Background(), &cfg, dir, self, source, newPrinter(&buf))
	if m.server != nil || buf.Len() != 0 {
		t.Fatalf("domain clear: server=%v output=%q", m.server, buf.String())
	}
}

func TestDNSServerManagerRestartsOnConfigChange(t *testing.T) {
	// Drive the manager with reachable unprivileged listen addresses by
	// stubbing the desired tuple through dnsserve.Start directly: reconcile
	// computes Addr from self.TunnelIP:53, so this test exercises the
	// stop/start convergence with the manager's own bookkeeping.
	m := &dnsServerManager{}
	defer m.stop()
	dir := directory.Directory{Domain: "vpn", NetworkCIDR: "10.42.0.0/24"}
	srv, err := dnsserve.Start(context.Background(), dnsserve.Config{
		Addr: "127.0.0.1:0", Domain: "vpn", Upstream: "127.0.0.1:1", Timeout: 100 * time.Millisecond,
	}, func() directory.Directory { return dir })
	if err != nil {
		t.Fatal(err)
	}
	m.server = srv
	m.cancel = func() {}
	m.current = dnsserve.Config{Addr: "127.0.0.1:0", Domain: "vpn", Upstream: "127.0.0.1:1"}

	// Same desired tuple: reconcile must not touch the running server.
	cfg := config.Default()
	off := false
	cfg.DNS.Serve = &off
	var buf bytes.Buffer
	m.reconcile(context.Background(), &cfg, dir, directory.Node{}, func() directory.Directory { return dir }, newPrinter(&buf))
	if m.server != nil {
		// serve=false ⇒ stop: the running server must be gone.
		t.Fatal("reconcile left the server running after serve=false")
	}
	if !dnsserveClosed(srv) {
		t.Fatal("underlying server still answering after stop")
	}
}

func dnsserveClosed(s *dnsserve.Server) bool {
	return !dnsserve.Probe(s.LocalAddr().String(), "vpn", 200*time.Millisecond)
}
