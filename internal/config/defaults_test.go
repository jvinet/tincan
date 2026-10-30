package config

import (
	"path/filepath"
	"testing"
)

func TestDNSProviderTTLDefaultsThroughConfigLoad(t *testing.T) {
	for _, provider := range []string{"desec", "linode"} {
		t.Run(provider, func(t *testing.T) {
			for _, explicit := range []int{0, 7200} {
				cfg := validConfig(t)
				cfg.Drop.Admin = DropBackend{Type: "dns", Zone: "example.com", Provider: provider, APIToken: "test", TTL: explicit}
				path := filepath.Join(t.TempDir(), "config.toml")
				if err := SaveMinimal(path, cfg); err != nil {
					t.Fatal(err)
				}
				loaded, err := Load(path)
				if err != nil {
					t.Fatal(err)
				}
				want := explicit
				if want == 0 {
					want = 300
					if provider == "desec" {
						want = 3600
					}
				}
				if loaded.Drop.Admin.TTL != want {
					t.Fatalf("TTL = %d, want %d", loaded.Drop.Admin.TTL, want)
				}
			}
		})
	}
}

func TestSaveMaterializesDNSHostsDefaults(t *testing.T) {
	cfg := validConfig(t)
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DNS.ManageHosts == nil || !*loaded.DNS.ManageHosts || loaded.DNS.HostsPath != "/etc/hosts" || loaded.DNS.Serve != nil {
		t.Fatalf("unexpected full DNS defaults: %+v", loaded.DNS)
	}
}
