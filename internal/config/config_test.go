package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jvinet/tincan/internal/keys"
)

func TestSaveLoadStrictConfig(t *testing.T) {
	cfg := validConfig(t)
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Wireguard.Name != "alice" || loaded.Drop.Admin.Type != "file" || loaded.Drop.Client.Type != "file" {
		t.Fatalf("unexpected config: %+v", loaded)
	}
	if loaded.Wireguard.Interface != DefaultInterface || loaded.Wireguard.MTU != DefaultMTU {
		t.Fatalf("defaults not applied: %+v", loaded.Wireguard)
	}
	if loaded.Sync.Cache != DefaultCachePath || loaded.Sync.PIDFile != DefaultPIDFile {
		t.Fatalf("sync defaults not applied: %+v", loaded.Sync)
	}
	if loaded.Sync.Interval.Duration != DefaultInterval {
		t.Fatalf("interval default not applied: %s", loaded.Sync.Interval.Duration)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", st.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "object_key") {
		t.Fatalf("file drop config should not contain object_key:\n%s", data)
	}
	data = append(data, []byte("\nunknown = true\n")...)
	badPath := filepath.Join(t.TempDir(), "bad.toml")
	if err := os.WriteFile(badPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(badPath); err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestLoadValidDropTypes(t *testing.T) {
	cases := []struct {
		name    string
		backend DropBackend
	}{
		{name: "file", backend: DropBackend{Type: "file", Path: filepath.Join(t.TempDir(), "directory.bin")}},
		{name: "http", backend: DropBackend{Type: "http", URL: "https://example.com/directory.bin", Username: "bob", Password: "secret"}},
		{name: "s3", backend: DropBackend{Type: "s3", Endpoint: "s3.amazonaws.com", Region: "us-east-1", Bucket: "tincan-net", AccessKey: "access", SecretKey: "secret"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Drop = DropConfig{Admin: tc.backend, Client: tc.backend}
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Drop.Client.Type != tc.backend.Type {
				t.Fatalf("drop client type = %q", loaded.Drop.Client.Type)
			}
			if tc.backend.Type == "s3" && loaded.Drop.Client.ObjectKey != "directory.bin" {
				t.Fatalf("s3 object key default = %q", loaded.Drop.Client.ObjectKey)
			}
		})
	}
}

func TestRejectMismatchedWGKeys(t *testing.T) {
	cfg := validConfig(t)
	_, cfg.Wireguard.PublicKey, _ = keys.GenerateWGKeypair()
	if err := cfg.Validate(false); err == nil {
		t.Fatal("expected mismatched WireGuard key error")
	}
}

func TestRejectMismatchedPublisherKeys(t *testing.T) {
	cfg := validConfig(t)
	_, wrongPrivate, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Directory.PublisherKey = wrongPrivate
	if err := cfg.Validate(false); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected publisher key mismatch, got %v", err)
	}
	if err := RequireAdmin(cfg); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected RequireAdmin mismatch, got %v", err)
	}
}

func TestRequireAdminRejectsMissingKey(t *testing.T) {
	cfg := validConfig(t)
	cfg.Directory.PublisherKey = ""
	if err := cfg.Validate(false); err != nil {
		t.Fatalf("client config should validate without publisher key: %v", err)
	}
	if err := RequireAdmin(cfg); err == nil {
		t.Fatal("expected missing admin key error")
	}
}

func TestRequireAdminRejectsMissingAdminDrop(t *testing.T) {
	cfg := validConfig(t)
	cfg.Drop.Admin = DropBackend{}
	if err := RequireAdmin(cfg); err == nil || !strings.Contains(err.Error(), "[drop.admin]") {
		t.Fatalf("expected missing admin drop error, got %v", err)
	}
}

func TestValidateRejectsBadDropFields(t *testing.T) {
	cases := []struct {
		name    string
		backend DropBackend
	}{
		{name: "unsupported", backend: DropBackend{Type: "ftp", URL: "ftp://example.com"}},
		{name: "file missing path", backend: DropBackend{Type: "file"}},
		{name: "file mixed fields", backend: DropBackend{Type: "file", Path: "/tmp/directory.bin", Endpoint: "s3.amazonaws.com"}},
		{name: "http missing URL", backend: DropBackend{Type: "http"}},
		{name: "http mixed fields", backend: DropBackend{Type: "http", URL: "https://example.com/directory.bin", Bucket: "bucket"}},
		{name: "s3 missing bucket", backend: DropBackend{Type: "s3", Endpoint: "s3.amazonaws.com"}},
		{name: "s3 partial credentials", backend: DropBackend{Type: "s3", Endpoint: "s3.amazonaws.com", Bucket: "bucket", AccessKey: "access"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Drop = DropConfig{Admin: tc.backend, Client: tc.backend}
			if err := cfg.Validate(false); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateAllowIncompleteSkipsDirectoryAndDrop(t *testing.T) {
	cfg := validConfig(t)
	cfg.Directory = DirectoryConfig{}
	cfg.Drop = DropConfig{}
	if err := cfg.Validate(true); err != nil {
		t.Fatalf("allowIncomplete should validate WireGuard-only config: %v", err)
	}
	if err := cfg.Validate(false); err == nil {
		t.Fatal("expected complete validation to fail")
	}
}

func validConfig(t *testing.T) Config {
	t.Helper()
	wgPriv, wgPub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	identity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Wireguard.Name = "alice"
	cfg.Wireguard.PrivateKey = wgPriv
	cfg.Wireguard.PublicKey = wgPub
	cfg.Directory.NetworkIdentity = identity
	cfg.Directory.PublisherPubKey = pub
	cfg.Directory.PublisherKey = priv
	backend := DropBackend{Type: "file", Path: filepath.Join(t.TempDir(), "directory.bin")}
	cfg.Drop = DropConfig{Admin: backend, Client: backend}
	return cfg
}
