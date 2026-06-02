//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/config"
	"github.com/pelletier/go-toml/v2"
)

func TestTwoNamespaceFileDropMVP(t *testing.T) {
	if os.Getenv("TINCAN_RUN_NETNS_INTEGRATION") != "1" {
		t.Skip("set TINCAN_RUN_NETNS_INTEGRATION=1 to run the privileged two-netns MVP test")
	}
	if os.Geteuid() != 0 {
		t.Skip("two-netns integration test requires root")
	}
	requireCommand(t, "go")
	requireCommand(t, "ip")
	requireCommand(t, "ping")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	root := repoRoot(t)
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "tincan")
	run(t, ctx, root, "go", "build", "-o", bin, "./cmd/tincan")

	suffix := fmt.Sprintf("%x", time.Now().UnixNano())
	if len(suffix) > 6 {
		suffix = suffix[len(suffix)-6:]
	}
	nsA := "tc-a-" + suffix
	nsB := "tc-b-" + suffix
	vethA := "tca" + suffix
	vethB := "tcb" + suffix

	run(t, ctx, "", "ip", "netns", "add", nsA)
	defer runIgnore(context.Background(), "", "ip", "netns", "del", nsA)
	run(t, ctx, "", "ip", "netns", "add", nsB)
	defer runIgnore(context.Background(), "", "ip", "netns", "del", nsB)
	run(t, ctx, "", "ip", "link", "add", vethA, "type", "veth", "peer", "name", vethB)
	run(t, ctx, "", "ip", "link", "set", vethA, "netns", nsA)
	run(t, ctx, "", "ip", "link", "set", vethB, "netns", nsB)
	run(t, ctx, "", "ip", "-n", nsA, "addr", "add", "192.0.2.1/30", "dev", vethA)
	run(t, ctx, "", "ip", "-n", nsB, "addr", "add", "192.0.2.2/30", "dev", vethB)
	run(t, ctx, "", "ip", "-n", nsA, "link", "set", "lo", "up")
	run(t, ctx, "", "ip", "-n", nsB, "link", "set", "lo", "up")
	run(t, ctx, "", "ip", "-n", nsA, "link", "set", vethA, "up")
	run(t, ctx, "", "ip", "-n", nsB, "link", "set", vethB, "up")

	if out, err := output(ctx, "", "ip", "netns", "exec", nsA, "ip", "link", "add", "tcwgprobe", "type", "wireguard"); err != nil {
		t.Skipf("wireguard kernel support unavailable: %v\n%s", err, out)
	}
	runIgnore(ctx, "", "ip", "netns", "exec", nsA, "ip", "link", "del", "tcwgprobe")

	dropPath := filepath.Join(tmp, "drop", "directory.bin")
	adminCfgPath := filepath.Join(tmp, "admin.toml")
	adminState := filepath.Join(tmp, "admin-state")
	runNS(t, ctx, nsA, bin, "--config", adminCfgPath, "init", "--name", "alice", "--drop-type", "file", "--cidr", "10.42.0.0/24", "--endpoint", "192.0.2.1:51820", "--state-dir", adminState)
	adminCfg, err := config.Load(adminCfgPath)
	if err != nil {
		t.Fatal(err)
	}
	adminCfg.Drop = config.DropConfig{Admin: config.DropBackend{Type: "file", Path: dropPath}, Client: config.DropBackend{Type: "file", Path: dropPath}}
	if err := config.Save(adminCfgPath, *adminCfg); err != nil {
		t.Fatal(err)
	}
	runNS(t, ctx, nsA, bin, "--config", adminCfgPath, "publish")

	addOut := runNS(t, ctx, nsA, bin, "--config", adminCfgPath, "add-node", "--name", "bob")
	bobPrivateKey := parsePrivateKey(t, addOut)
	bobKeyPath := filepath.Join(tmp, "bob.key")
	if err := os.WriteFile(bobKeyPath, []byte(bobPrivateKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	bobCfgPath := filepath.Join(tmp, "bob.toml")
	bobState := filepath.Join(tmp, "bob-state")
	runNS(t, ctx, nsB, bin, "--config", bobCfgPath, "join", "--drop-type", "file", "--name", "bob", "--private-key-file", bobKeyPath, "--state-dir", bobState)
	bobCfg := readLooseConfig(t, bobCfgPath)
	bobCfg.Directory.NetworkIdentity = adminCfg.Directory.NetworkIdentity
	bobCfg.Directory.PublisherPubKey = adminCfg.Directory.PublisherPubKey
	bobCfg.Drop = config.DropConfig{Admin: config.DropBackend{Type: "file", Path: dropPath}, Client: config.DropBackend{Type: "file", Path: dropPath}}
	if err := config.Save(bobCfgPath, bobCfg); err != nil {
		t.Fatal(err)
	}

	runNS(t, ctx, nsB, bin, "--config", bobCfgPath, "sync", "--once")
	runNS(t, ctx, nsA, bin, "--config", adminCfgPath, "sync", "--once")
	run(t, ctx, "", "ip", "netns", "exec", nsB, "ping", "-c", "3", "-W", "2", "10.42.0.1")
}

func requireCommand(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found: %v", name, err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func runNS(t *testing.T, ctx context.Context, ns string, args ...string) string {
	t.Helper()
	cmdArgs := append([]string{"netns", "exec", ns}, args...)
	return run(t, ctx, "", "ip", cmdArgs...)
}

func run(t *testing.T, ctx context.Context, dir string, name string, args ...string) string {
	t.Helper()
	out, err := output(ctx, dir, name, args...)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func output(ctx context.Context, dir string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runIgnore(ctx context.Context, dir string, name string, args ...string) {
	_, _ = output(ctx, dir, name, args...)
}

func parsePrivateKey(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if key, ok := strings.CutPrefix(line, "WireGuard private key: "); ok {
			return strings.TrimSpace(key)
		}
	}
	t.Fatalf("add-node output did not include generated private key:\n%s", out)
	return ""
}

func readLooseConfig(t *testing.T, path string) config.Config {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cfg := config.Default()
	if err := toml.NewDecoder(f).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ApplyDefaults()
	return cfg
}
