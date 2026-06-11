package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/drop"
	"github.com/jvinet/tincan/internal/keys"
)

// setDomainFixture publishes dir and saves the admin config, returning the
// config path and the loaded config for drop access.
func setDomainFixture(t *testing.T, mutate func(*directory.Directory)) (string, *config.Config) {
	t.Helper()
	admin, dir := testFlowConfigAndDirectory(t, 1)
	if mutate != nil {
		mutate(&dir)
	}
	publishTestDirectory(t, admin, dir)
	if err := cache.WriteSource(admin.Sync.StateDir, dir); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "admin.toml")
	if err := config.Save(cfgPath, *admin); err != nil {
		t.Fatal(err)
	}
	return cfgPath, admin
}

func publishedDirectory(t *testing.T, cfg *config.Config) directory.Directory {
	t.Helper()
	d, err := drop.New(cfg.Drop.Admin)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := d.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir, _, err := directory.Open(blob, cfg.Directory.NetworkIdentity, cfg.Directory.PublisherPubKey)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSetDomainPublishes(t *testing.T) {
	cfgPath, cfg := setDomainFixture(t, nil)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", cfgPath, "set-domain", "VPN.Home."}, &stdout, &stderr); code != 0 {
		t.Fatalf("set-domain exit=%d stderr=%q", code, stderr.String())
	}
	dir := publishedDirectory(t, cfg)
	if dir.Domain != "vpn.home" {
		t.Fatalf("published domain = %q, want normalized %q", dir.Domain, "vpn.home")
	}
	if dir.Serial != 2 {
		t.Fatalf("serial = %d, want 2 (bumped)", dir.Serial)
	}

	// Show now reports it (commands print to os.Stdout, so drive the helper
	// with a buffer-backed printer instead of run()).
	var shown bytes.Buffer
	if err := (&SetDomainCmd{}).show(context.Background(), cfg, newPrinter(&shown)); err != nil {
		t.Fatalf("show: %v", err)
	}
	if !strings.Contains(shown.String(), "vpn.home") {
		t.Fatalf("show output missing domain:\n%s", shown.String())
	}

	// Clear empties it and bumps again.
	if code := run([]string{"-c", cfgPath, "set-domain", "--clear"}, &stdout, &stderr); code != 0 {
		t.Fatalf("clear exit=%d stderr=%q", code, stderr.String())
	}
	dir = publishedDirectory(t, cfg)
	if dir.Domain != "" || dir.Serial != 3 {
		t.Fatalf("after clear: domain=%q serial=%d, want empty at serial 3", dir.Domain, dir.Serial)
	}
}

func TestSetDomainListsAllBadNames(t *testing.T) {
	cfgPath, cfg := setDomainFixture(t, func(d *directory.Directory) {
		_, pub1, _ := keys.GenerateWGKeypair()
		_, pub2, _ := keys.GenerateWGKeypair()
		_, pub3, _ := keys.GenerateWGKeypair()
		d.Nodes = append(d.Nodes,
			directory.Node{Name: "My Laptop", PublicKey: pub1, TunnelIP: "10.42.0.2"},
			directory.Node{Name: "db_2", PublicKey: pub2, TunnelIP: "10.42.0.3"},
			directory.Node{Name: "Alice", PublicKey: pub3, TunnelIP: "10.42.0.4"}, // collides with "alice"
		)
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", cfgPath, "set-domain", "vpn"}, &stdout, &stderr); code == 0 {
		t.Fatal("set-domain succeeded with un-DNS-able names")
	}
	out := stderr.String()
	for _, want := range []string{"My Laptop", "db_2", "Alice"} {
		if !strings.Contains(out, want) {
			t.Fatalf("error does not name offender %q:\n%s", want, out)
		}
	}
	if dir := publishedDirectory(t, cfg); dir.Domain != "" || dir.Serial != 1 {
		t.Fatalf("refused set-domain still mutated the directory: %+v", dir)
	}
}

func TestSetDomainRejectsInvalidDomain(t *testing.T) {
	cfgPath, _ := setDomainFixture(t, nil)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", cfgPath, "set-domain", "not a domain"}, &stdout, &stderr); code == 0 {
		t.Fatal("set-domain accepted an invalid domain")
	}
	if code := run([]string{"-c", cfgPath, "set-domain", "vpn", "--clear"}, &stdout, &stderr); code == 0 {
		t.Fatal("set-domain accepted --clear with a domain argument")
	}
}

func TestSetDomainNoPublishWritesSourceOnly(t *testing.T) {
	cfgPath, cfg := setDomainFixture(t, nil)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", cfgPath, "set-domain", "vpn", "--no-publish"}, &stdout, &stderr); code != 0 {
		t.Fatalf("set-domain exit=%d stderr=%q", code, stderr.String())
	}
	if dir := publishedDirectory(t, cfg); dir.Domain != "" {
		t.Fatalf("--no-publish still published: %+v", dir)
	}
	source, err := cache.ReadSource(cfg.Sync.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if source.Domain != "vpn" {
		t.Fatalf("source domain = %q, want %q", source.Domain, "vpn")
	}
}

func TestWarnStrandedSpokesNamesPlainWGNodes(t *testing.T) {
	_, pub, _ := keys.GenerateWGKeypair()
	_, pub2, _ := keys.GenerateWGKeypair()
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "alice", PublicKey: pub2, TunnelIP: "10.42.0.1", AgeRecipient: "age1member"},
		{Name: "phone", PublicKey: pub, TunnelIP: "10.42.0.9"}, // no AgeRecipient: plain-WG spoke
	}}
	var buf bytes.Buffer
	warnStrandedSpokes(newPrinter(&buf), dir)
	if !strings.Contains(buf.String(), "phone") || strings.Contains(buf.String(), "alice") {
		t.Fatalf("warning should name spokes and only spokes:\n%s", buf.String())
	}
	// No spokes, no warning.
	buf.Reset()
	warnStrandedSpokes(newPrinter(&buf), directory.Directory{Nodes: dir.Nodes[:1]})
	if buf.Len() != 0 {
		t.Fatalf("unexpected warning with no spokes:\n%s", buf.String())
	}
}

func TestAddNodeRejectsUnDNSableNames(t *testing.T) {
	cfgPath, _ := setDomainFixture(t, nil)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", cfgPath, "add-node", "--name", "my laptop"}, &stdout, &stderr); code == 0 {
		t.Fatal("add-node accepted a name that is not a DNS label")
	}
	if !strings.Contains(stderr.String(), "DNS label") {
		t.Fatalf("error does not explain the DNS-label rule:\n%s", stderr.String())
	}
}

func TestAddNodeRejectsCaseCollisionWithDomain(t *testing.T) {
	cfgPath, _ := setDomainFixture(t, func(d *directory.Directory) { d.Domain = "vpn" })
	var stdout, stderr bytes.Buffer
	// Fixture directory already contains "alice".
	if code := run([]string{"-c", cfgPath, "add-node", "--name", "Alice"}, &stdout, &stderr); code == 0 {
		t.Fatal("add-node accepted a case-colliding name while a domain is set")
	}
	if !strings.Contains(stderr.String(), "case-insensitive") {
		t.Fatalf("error does not explain the collision:\n%s", stderr.String())
	}
}
