package cli

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/jvinet/tincan/internal/bootstrap"
	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/keys"
)

// enroll runs the admin's `add-node` and the client's `join` against a file
// drop, mirroring the real workflow, and returns the bootstrap the admin
// produced together with the config `join` wrote. endpoint may be empty.
func enroll(t *testing.T, endpoint string) (bootstrap.Bootstrap, *config.Config) {
	t.Helper()
	admin, dir := testFlowConfigAndDirectory(t, 1)
	if err := cache.WriteSource(admin.Sync.StateDir, dir); err != nil {
		t.Fatalf("write source: %v", err)
	}
	adminCfg := filepath.Join(t.TempDir(), "admin.toml")
	if err := config.Save(adminCfg, *admin); err != nil {
		t.Fatalf("save admin config: %v", err)
	}

	bsPath := filepath.Join(t.TempDir(), "tau.json")
	args := []string{"-c", adminCfg, "add-node", "--name", "tau", "--bootstrap", bsPath, "--no-publish"}
	if endpoint != "" {
		args = append(args, "--endpoint", endpoint)
	}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("add-node exit=%d; stderr=%q", code, stderr.String())
	}
	bs, err := bootstrap.Read(bsPath)
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}

	clientCfg := filepath.Join(t.TempDir(), "client.toml")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-c", clientCfg, "join", "--bootstrap", bsPath, "--state-dir", t.TempDir()}, &stdout, &stderr); code != 0 {
		t.Fatalf("join exit=%d; stderr=%q", code, stderr.String())
	}
	cfg, err := config.Load(clientCfg)
	if err != nil {
		t.Fatalf("load client config: %v", err)
	}
	return bs, cfg
}

// The port in `add-node --endpoint host:port` must reach the joined client as
// its WireGuard listen port; otherwise the node binds an ephemeral port and is
// unreachable at the endpoint the admin published for it.
func TestEnrollCarriesEndpointPortAsListenPort(t *testing.T) {
	bs, cfg := enroll(t, "203.0.113.7:50000")
	if bs.Node == nil {
		t.Fatal("bootstrap has no node")
	}
	if bs.Node.ListenPort != 50000 {
		t.Fatalf("bootstrap listen port=%d, want 50000", bs.Node.ListenPort)
	}
	if cfg.Wireguard.ListenPort != 50000 {
		t.Fatalf("joined config listen port=%d, want 50000", cfg.Wireguard.ListenPort)
	}
}

// A node added without an endpoint has no fixed port; the joined client must
// leave listen_port unset so WireGuard chooses an ephemeral one.
func TestEnrollWithoutEndpointLeavesListenPortUnset(t *testing.T) {
	bs, cfg := enroll(t, "")
	if bs.Node == nil {
		t.Fatal("bootstrap has no node")
	}
	if bs.Node.ListenPort != 0 {
		t.Fatalf("bootstrap listen port=%d, want 0", bs.Node.ListenPort)
	}
	if cfg.Wireguard.ListenPort != 0 {
		t.Fatalf("joined config listen port=%d, want 0", cfg.Wireguard.ListenPort)
	}
}

// The bootstrap carries the directory serial current at enrollment, and join
// must seed the client's rollback high-water mark with it — otherwise the
// node's first sync would accept an arbitrarily old signed directory.
func TestEnrollSeedsSerialFloor(t *testing.T) {
	bs, cfg := enroll(t, "")
	if bs.Serial != 1 {
		t.Fatalf("bootstrap serial=%d, want 1", bs.Serial)
	}
	serial, err := cache.ReadSerial(cfg.Sync.StateDir)
	if err != nil {
		t.Fatalf("read seeded serial: %v", err)
	}
	if serial != bs.Serial {
		t.Fatalf("seeded serial=%d, want %d", serial, bs.Serial)
	}
}

// add-node generates the node's age keypair, delivers the identity in the
// bootstrap, and join writes it as the node's own network_identity. Without
// this the node has no key to decrypt the per-node-encrypted directory.
func TestEnrollWiresAgeIdentity(t *testing.T) {
	bs, cfg := enroll(t, "")
	if bs.Node == nil || bs.Node.AgeIdentity == "" {
		t.Fatal("bootstrap did not carry an age identity")
	}
	if cfg.Directory.NetworkIdentity != bs.Node.AgeIdentity {
		t.Fatalf("joined network_identity %q != bootstrap age identity %q", cfg.Directory.NetworkIdentity, bs.Node.AgeIdentity)
	}
	if _, err := keys.AgeRecipientFromIdentity(cfg.Directory.NetworkIdentity); err != nil {
		t.Fatalf("joined identity is not a valid age identity: %v", err)
	}
}

// A malformed --endpoint must fail before the node is added to the directory,
// so a bad port leaves no half-enrolled node behind.
func TestAddNodeRejectsMalformedEndpoint(t *testing.T) {
	admin, dir := testFlowConfigAndDirectory(t, 1)
	if err := cache.WriteSource(admin.Sync.StateDir, dir); err != nil {
		t.Fatalf("write source: %v", err)
	}
	adminCfg := filepath.Join(t.TempDir(), "admin.toml")
	if err := config.Save(adminCfg, *admin); err != nil {
		t.Fatalf("save admin config: %v", err)
	}
	bsPath := filepath.Join(t.TempDir(), "tau.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-c", adminCfg, "add-node", "--name", "tau",
		"--endpoint", "203.0.113.7", // no port
		"--bootstrap", bsPath, "--no-publish",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("add-node accepted a portless endpoint; stdout=%q", stdout.String())
	}
	src, err := cache.ReadSource(admin.Sync.StateDir)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if _, _, ok := nodeByName(src, "tau"); ok {
		t.Fatal("malformed endpoint left a half-added node in the directory")
	}
}
