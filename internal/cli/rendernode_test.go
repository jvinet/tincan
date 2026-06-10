package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/drop"
	"github.com/jvinet/tincan/internal/keys"
)

// publishTestDirectory seals dir with the admin's publisher key and writes it
// to the admin drop, so read commands fetch it like a real published directory.
func publishTestDirectory(t *testing.T, cfg *config.Config, dir directory.Directory) {
	t.Helper()
	blob, err := directory.Seal(dir, cfg.Directory.PublisherKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	d, err := drop.New(cfg.Drop.Admin)
	if err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := d.Put(context.Background(), blob); err != nil {
		t.Fatalf("put: %v", err)
	}
}

// renderNodeFixture publishes a directory whose admin (alice) is a relay hub and
// adds a plain-WireGuard spoke named "phone", returning the admin config path
// and the phone's generated private key.
func renderNodeFixture(t *testing.T) (adminCfg, phonePriv string) {
	t.Helper()
	admin, dir := testFlowConfigAndDirectory(t, 1)
	dir.Nodes[0].Endpoint = "alice.example:51820"
	dir.Nodes[0].Relay = true
	priv, pub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	dir.Nodes = append(dir.Nodes, directory.Node{Name: "phone", PublicKey: pub, TunnelIP: "10.42.0.50"})
	publishTestDirectory(t, admin, dir)
	adminCfg = filepath.Join(t.TempDir(), "admin.toml")
	if err := config.Save(adminCfg, *admin); err != nil {
		t.Fatal(err)
	}
	return adminCfg, priv
}

func TestRenderNodeWritesConfig(t *testing.T) {
	adminCfg, phonePriv := renderNodeFixture(t)

	// The rendered text is written to os.Stdout (not the run() buffers), so
	// assert on the --wg-config file, which also covers the file-writing path.
	render := func(t *testing.T, path string, args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		full := append([]string{"-c", adminCfg, "render-node", "--name", "phone", "--wg-config", path}, args...)
		if code := run(full, &stdout, &stderr); code != 0 {
			t.Fatalf("render-node %v exit=%d stderr=%q", args, code, stderr.String())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read rendered config: %v", err)
		}
		return string(data)
	}

	// No --private-key: a template carrying a fill-in placeholder.
	tmpl := render(t, filepath.Join(t.TempDir(), "phone.conf"))
	for _, want := range []string{"# PrivateKey =", "Address = 10.42.0.50/32", "Endpoint = alice.example:51820", "AllowedIPs = 10.42.0.0/24"} {
		if !strings.Contains(tmpl, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, tmpl)
		}
	}

	// With the matching --private-key the real key is embedded, no placeholder.
	keyed := render(t, filepath.Join(t.TempDir(), "phone-keyed.conf"), "--private-key", phonePriv)
	if !strings.Contains(keyed, "PrivateKey = "+phonePriv) {
		t.Fatalf("expected embedded private key:\n%s", keyed)
	}
	if strings.Contains(keyed, "# PrivateKey") {
		t.Fatalf("placeholder leaked despite a supplied key:\n%s", keyed)
	}
}

func TestRenderNodeRejectsMismatchedKey(t *testing.T) {
	adminCfg, _ := renderNodeFixture(t)
	wrongPriv, _, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", adminCfg, "render-node", "--name", "phone", "--private-key", wrongPriv}, &stdout, &stderr); code == 0 {
		t.Fatalf("render-node accepted a mismatched private key; stdout=%q", stdout.String())
	}
}

func TestRenderNodeUnknownNode(t *testing.T) {
	adminCfg, _ := renderNodeFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", adminCfg, "render-node", "--name", "ghost"}, &stdout, &stderr); code == 0 {
		t.Fatal("render-node accepted an unknown node name")
	}
}

func TestRenderNodeValidateFlags(t *testing.T) {
	tests := []struct {
		name string
		cmd  RenderNodeCmd
		ok   bool
	}{
		{"bare stdout template", RenderNodeCmd{Name: "n"}, true},
		{"config file template", RenderNodeCmd{Name: "n", WGConfig: "n.conf"}, true},
		{"qr without key", RenderNodeCmd{Name: "n", WGQR: true}, false},
		{"qr-png without key", RenderNodeCmd{Name: "n", WGQRPNG: "n.png"}, false},
		{"qr with key", RenderNodeCmd{Name: "n", WGQR: true, PrivateKey: "k"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.validateFlags()
			if tt.ok && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}
