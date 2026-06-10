package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jvinet/tincan/internal/config"
)

func TestNodeListenPortRoundTrips(t *testing.T) {
	base := Bootstrap{
		SchemaVersion: SchemaVersion,
		Directory:     Directory{PublisherPubKey: "pub"},
		Drop:          config.DropBackend{Type: "file", Path: "/tmp/drop.bin"},
	}
	b := WithNode(base, Node{
		Name:        "tau",
		TunnelIP:    "10.42.0.7",
		ListenPort:  50000,
		PublicKey:   "pk",
		PrivateKey:  "sk",
		AgeIdentity: "AGE-SECRET-KEY-1TEST",
	})

	path := filepath.Join(t.TempDir(), "tau.json")
	if err := Write(path, b); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Node == nil {
		t.Fatal("read bootstrap has no node")
	}
	if got.Node.ListenPort != 50000 {
		t.Fatalf("listen port=%d, want 50000", got.Node.ListenPort)
	}
	if got.Node.AgeIdentity != "AGE-SECRET-KEY-1TEST" {
		t.Fatalf("age identity=%q, want round-trip", got.Node.AgeIdentity)
	}
}

// A node without a published endpoint has no fixed listen port; the field must
// stay out of the JSON so NAT'd-client bootstraps remain compact (and so `join`
// leaves the port unset, letting WireGuard pick an ephemeral one).
func TestNodeListenPortOmittedWhenZero(t *testing.T) {
	base := Bootstrap{SchemaVersion: SchemaVersion, Drop: config.DropBackend{Type: "file", Path: "/tmp/drop.bin"}}
	b := WithNode(base, Node{Name: "leaf", TunnelIP: "10.42.0.8", PublicKey: "pk"})

	path := filepath.Join(t.TempDir(), "leaf.json")
	if err := Write(path, b); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "listen_port") {
		t.Fatalf("zero listen port should be omitted from JSON:\n%s", data)
	}
}
