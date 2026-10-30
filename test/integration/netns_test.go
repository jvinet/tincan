//go:build linux && integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
)

func TestTwoNamespaceFileDrop(t *testing.T) {
	if os.Getenv("TINCAN_RUN_NETNS_INTEGRATION") != "1" {
		t.Skip("set TINCAN_RUN_NETNS_INTEGRATION=1 (or use make test-integration) to run privileged networking tests")
	}
	if os.Geteuid() != 0 {
		t.Fatal("network-namespace integration tests require root and CAP_NET_ADMIN")
	}
	for _, command := range []string{"go", "ip", "ping"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatalf("required command %s: %v", command, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "tincan")
	run(t, ctx, root, "go", "build", "-o", bin, "./cmd/tincan")

	suffix := fmt.Sprintf("%x", time.Now().UnixNano())
	suffix = suffix[len(suffix)-6:]
	nsA, nsB := "tc-a-"+suffix, "tc-b-"+suffix
	vethA, vethB := "tca"+suffix, "tcb"+suffix
	for _, ns := range []string{nsA, nsB} {
		run(t, ctx, "", "ip", "netns", "add", ns)
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = output(cleanupCtx, "", "ip", "netns", "del", ns)
		})
	}
	run(t, ctx, "", "ip", "link", "add", vethA, "type", "veth", "peer", "name", vethB)
	run(t, ctx, "", "ip", "link", "set", vethA, "netns", nsA)
	run(t, ctx, "", "ip", "link", "set", vethB, "netns", nsB)
	for i, pair := range [][2]string{{nsA, vethA}, {nsB, vethB}} {
		run(t, ctx, "", "ip", "-n", pair[0], "addr", "add", fmt.Sprintf("192.0.2.%d/30", i+1), "dev", pair[1])
		run(t, ctx, "", "ip", "-n", pair[0], "link", "set", "lo", "up")
		run(t, ctx, "", "ip", "-n", pair[0], "link", "set", pair[1], "up")
	}

	dropPath := filepath.Join(tmp, "drop", "directory.bin")
	adminPath := filepath.Join(tmp, "admin.toml")
	runNS(t, ctx, nsA, bin, "-c", adminPath, "init", "--name", "alice", "--drop-type", "file", "--endpoint", "192.0.2.1:51820", "--state-dir", filepath.Join(tmp, "admin-state"))
	admin, err := config.Load(adminPath)
	if err != nil {
		t.Fatal(err)
	}
	backend := config.DropBackend{Type: "file", Path: dropPath}
	admin.Drop = config.DropConfig{Admin: backend, Client: backend}
	unmanaged := false // never change the host's /etc/hosts from a network namespace
	admin.DNS.ManageHosts = &unmanaged
	if err := config.Save(adminPath, *admin); err != nil {
		t.Fatal(err)
	}
	runNS(t, ctx, nsA, bin, "-c", adminPath, "publish")

	bootstrapPath := filepath.Join(tmp, "bob.json")
	runNS(t, ctx, nsA, bin, "-c", adminPath, "add-node", "--name", "bob", "--bootstrap", bootstrapPath)
	clientPath := filepath.Join(tmp, "bob.toml")
	runNS(t, ctx, nsB, bin, "-c", clientPath, "join", "--bootstrap", bootstrapPath, "--state-dir", filepath.Join(tmp, "bob-state"))
	client, err := config.Load(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if client.Directory.NetworkIdentity == admin.Directory.NetworkIdentity {
		t.Fatal("enrollment shared the admin's identity instead of using Bob's own key")
	}
	client.DNS.ManageHosts = &unmanaged
	if err := config.Save(clientPath, *client); err != nil {
		t.Fatal(err)
	}
	runNS(t, ctx, nsA, bin, "-c", adminPath, "up")
	runNS(t, ctx, nsB, bin, "-c", clientPath, "up")
	runNS(t, ctx, nsB, "ping", "-c", "3", "-W", "2", "10.42.0.1")
	runNS(t, ctx, nsA, "ping", "-c", "3", "-W", "2", "10.42.0.2")
	oldBlob := readFile(t, dropPath)

	// sync must update only the cache. Applying the cache is a separate step.
	runNS(t, ctx, nsA, bin, "-c", adminPath, "add-node", "--name", "carol", "--bootstrap", filepath.Join(tmp, "carol.json"))
	runNS(t, ctx, nsB, bin, "-c", clientPath, "sync")
	assertPeerCount(t, ctx, nsB, bin, clientPath, 1)
	runNS(t, ctx, nsB, bin, "-c", clientPath, "up", "--no-sync")
	assertPeerCount(t, ctx, nsB, bin, clientPath, 2)
	runNS(t, ctx, nsA, bin, "-c", adminPath, "remove-node", "--name", "carol")
	runNS(t, ctx, nsB, bin, "-c", clientPath, "up")
	assertPeerCount(t, ctx, nsB, bin, clientPath, 1)
	currentBlob := readFile(t, dropPath)

	// A missing drop must still permit an offline apply and working traffic.
	if err := os.Remove(dropPath); err != nil {
		t.Fatal(err)
	}
	runNS(t, ctx, nsB, bin, "-c", clientPath, "up")
	runNS(t, ctx, nsB, "ping", "-c", "1", "-W", "2", "10.42.0.1")
	writeFile(t, dropPath, oldBlob)
	out, err := output(ctx, "", "ip", "netns", "exec", nsB, bin, "-c", clientPath, "sync")
	if err == nil || !strings.Contains(out, "stale serial") {
		t.Fatalf("rollback was not rejected: err=%v output=%s", err, out)
	}
	assertPeerCount(t, ctx, nsB, bin, clientPath, 1)
	writeFile(t, dropPath, currentBlob)

	// Removal revokes both directory decryption and the live WireGuard peer.
	runNS(t, ctx, nsA, bin, "-c", adminPath, "remove-node", "--name", "bob")
	if _, _, err := directory.Open(readFile(t, dropPath), client.Directory.NetworkIdentity, client.Directory.PublisherPubKey); err == nil {
		t.Fatal("removed Bob still decrypts the directory")
	}
	runNS(t, ctx, nsA, bin, "-c", adminPath, "up")
	assertPeerCount(t, ctx, nsA, bin, adminPath, 0)
	if out, err := output(ctx, "", "ip", "netns", "exec", nsB, "ping", "-c", "1", "-W", "1", "10.42.0.1"); err == nil {
		t.Fatalf("revoked peer still reached the admin: %s", out)
	}
	for _, pair := range [][2]string{{nsA, adminPath}, {nsB, clientPath}} {
		runNS(t, ctx, pair[0], bin, "-c", pair[1], "down")
	}
}

func assertPeerCount(t *testing.T, ctx context.Context, ns, bin, configPath string, want int) {
	t.Helper()
	out := runNS(t, ctx, ns, bin, "-c", configPath, "status", "--json")
	var status struct {
		WireGuard struct {
			PeerCount *int `json:"peer_count"`
		} `json:"wireguard"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("decode status: %v\n%s", err, out)
	}
	if status.WireGuard.PeerCount == nil || *status.WireGuard.PeerCount != want {
		t.Fatalf("expected %d live peers:\n%s", want, out)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func runNS(t *testing.T, ctx context.Context, ns string, args ...string) string {
	t.Helper()
	return run(t, ctx, "", "ip", append([]string{"netns", "exec", ns}, args...)...)
}

func run(t *testing.T, ctx context.Context, dir, name string, args ...string) string {
	t.Helper()
	out, err := output(ctx, dir, name, args...)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func output(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
