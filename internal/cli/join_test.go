package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/jvinet/tincan/internal/bootstrap"
	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/keys"
)

func TestBootstrapCompletesLocallyGeneratedEnrollment(t *testing.T) {
	for _, withKeyFile := range []bool{false, true} {
		t.Run(map[bool]string{false: "reuse keys", true: "explicit key file"}[withKeyFile], func(t *testing.T) {
			clientPath := filepath.Join(t.TempDir(), "client.toml")
			stateDir := t.TempDir()
			runAdminCLI(t, clientPath, "join", "--name", "bob", "--drop-type", "file", "--generate-key", "--state-dir", stateDir)
			original, err := config.LoadIncomplete(clientPath)
			if err != nil {
				t.Fatal(err)
			}
			original.Wireguard.MTU = 1380
			original.Discovery.Enabled = boolPtr(false)
			if err := config.SaveMinimal(clientPath, *original); err != nil {
				t.Fatal(err)
			}
			recipient, err := keys.AgeRecipientFromIdentity(original.Directory.NetworkIdentity)
			if err != nil {
				t.Fatal(err)
			}
			adminPath, _ := setDomainFixture(t, nil)
			bsPath := filepath.Join(t.TempDir(), "bob.json")
			runAdminCLI(t, adminPath, "add-node", "--name", "bob", "--pub-key", original.Wireguard.PublicKey, "--age-recipient", recipient, "--endpoint", "192.0.2.2:50000", "--bootstrap", bsPath)
			args := []string{"join", "--bootstrap", bsPath, "--force"}
			if withKeyFile {
				keyFile := filepath.Join(t.TempDir(), "wg.key")
				if err := os.WriteFile(keyFile, []byte(original.Wireguard.PrivateKey), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--private-key-file", keyFile)
			}
			runAdminCLI(t, clientPath, args...)
			joined, err := config.Load(clientPath)
			if err != nil {
				t.Fatal(err)
			}
			if joined.Directory.NetworkIdentity != original.Directory.NetworkIdentity || joined.Wireguard.PrivateKey != original.Wireguard.PrivateKey {
				t.Fatal("bootstrap enrollment replaced locally generated keys")
			}
			if joined.Sync.StateDir != stateDir || joined.Wireguard.MTU != 1380 || joined.Discovery.IsEnabled() || joined.Wireguard.ListenPort != 50000 {
				t.Fatal("bootstrap did not preserve local policy or apply its listen port")
			}
			bs, err := bootstrap.Read(bsPath)
			if err != nil {
				t.Fatal(err)
			}
			floor, err := cache.ReadSerial(stateDir)
			if err != nil || floor != bs.Serial {
				t.Fatalf("serial floor = %d, err = %v", floor, err)
			}
			// This also proves that the preserved age identity is a recipient,
			// not merely a syntactically valid but unrelated key.
			runAdminCLI(t, clientPath, "sync")
		})
	}
}

func TestBootstrapMismatchLeavesExistingKeysUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.toml")
	runAdminCLI(t, path, "join", "--name", "bob", "--drop-type", "file", "--generate-key")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	bsPath := filepath.Join(t.TempDir(), "wrong.json")
	if err := bootstrap.Write(bsPath, bootstrap.Bootstrap{SchemaVersion: bootstrap.SchemaVersion, Node: &bootstrap.Node{Name: "bob", PublicKey: wrongPub}}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", path, "join", "--bootstrap", bsPath, "--force"}, &stdout, &stderr); code == 0 {
		t.Fatal("accepted bootstrap for a different local key")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("mismatched bootstrap overwrote the existing config")
	}
}
