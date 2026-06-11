package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
)

func hostsSyncFixture(t *testing.T) (*config.Config, directory.Directory, string) {
	t.Helper()
	cfg := config.Default()
	path := filepath.Join(t.TempDir(), "hosts")
	cfg.DNS.HostsPath = path
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := directory.Directory{
		Domain: "vpn",
		Nodes: []directory.Node{
			{Name: "alice", TunnelIP: "10.42.0.1"},
			{Name: "bob", TunnelIP: "10.42.0.2"},
		},
	}
	return &cfg, dir, path
}

func TestHostsSyncerAppliesAndRemoves(t *testing.T) {
	cfg, dir, path := hostsSyncFixture(t)
	var buf bytes.Buffer
	h := &hostsSyncer{}
	h.sync(cfg, dir, newPrinter(&buf))
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "10.42.0.2\tbob.vpn") {
		t.Fatalf("hosts block not applied:\n%s", data)
	}

	// Domain cleared: the same sync path strips the block.
	dir.Domain = ""
	h.sync(cfg, dir, newPrinter(&buf))
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "tincan") {
		t.Fatalf("hosts block not removed after domain clear:\n%s", data)
	}
}

func TestHostsSyncerRespectsManageHostsOff(t *testing.T) {
	cfg, dir, path := hostsSyncFixture(t)
	off := false
	cfg.DNS.ManageHosts = &off
	var buf bytes.Buffer
	(&hostsSyncer{}).sync(cfg, dir, newPrinter(&buf))
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "tincan") {
		t.Fatalf("manage_hosts=false still wrote the block:\n%s", data)
	}
}

func TestHostsSyncerDedupesWarnings(t *testing.T) {
	cfg, dir, _ := hostsSyncFixture(t)
	// Point at a path whose parent directory doesn't exist so Apply fails the
	// same way every iteration.
	cfg.DNS.HostsPath = filepath.Join(t.TempDir(), "missing", "hosts")
	var buf bytes.Buffer
	h := &hostsSyncer{}
	h.sync(cfg, dir, newPrinter(&buf))
	first := buf.String()
	if !strings.Contains(first, "could not update") {
		t.Fatalf("expected a warning, got:\n%s", first)
	}
	h.sync(cfg, dir, newPrinter(&buf))
	if buf.String() != first {
		t.Fatalf("repeated failure warned twice:\n%s", buf.String())
	}
}

func TestRemoveHostsBlock(t *testing.T) {
	cfg, dir, path := hostsSyncFixture(t)
	var buf bytes.Buffer
	(&hostsSyncer{}).sync(cfg, dir, newPrinter(&buf))
	removeHostsBlock(cfg, newPrinter(&buf))
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "tincan") || !strings.Contains(string(data), "localhost") {
		t.Fatalf("removeHostsBlock left traces or ate content:\n%s", data)
	}
}
