package config

import (
	"fmt"
	"path/filepath"
	"time"
)

const (
	DefaultConfigPath = "/etc/tincan/config.toml"
	DefaultStateDir   = "/var/lib/tincan"
	DefaultCachePath  = DefaultStateDir + "/cache.bin"
	DefaultPIDFile    = "/run/tincan.pid"
	DefaultInterface  = "tincan0"
	DefaultMTU        = 1420
	DefaultInterval   = 5 * time.Minute
	DefaultNetwork    = "10.42.0.0/24"

	DefaultDiscoveryMulticastIPv4  = "239.255.84.67:51821"
	DefaultDiscoveryMulticastIPv6  = "[ff02::1:8443]:51821"
	DefaultDiscoveryBeaconInterval = 30 * time.Second
	DefaultDiscoveryBeaconTTL      = 90 * time.Second
)

type Config struct {
	Wireguard WireguardConfig `toml:"wireguard"`
	Directory DirectoryConfig `toml:"directory"`
	Drop      DropConfig      `toml:"drop"`
	Sync      SyncConfig      `toml:"sync"`
	Observe   ObserveConfig   `toml:"observe,omitempty"`
	Discovery DiscoveryConfig `toml:"discovery,omitempty"`
}

type WireguardConfig struct {
	Name       string           `toml:"name"`
	PublicKey  string           `toml:"public_key"`
	PrivateKey string           `toml:"private_key"`
	Interface  string           `toml:"interface,omitempty"`
	ListenPort int              `toml:"listen_port,omitempty"`
	MTU        int              `toml:"mtu,omitempty"`
	Keepalive  OptionalDuration `toml:"keepalive,omitempty"`
}

type DirectoryConfig struct {
	NetworkIdentity string `toml:"network_identity"`
	PublisherPubKey string `toml:"publisher_pubkey"`
	PublisherKey    string `toml:"publisher_key,omitempty"`
}

type DropConfig struct {
	Admin  DropBackend `toml:"admin,omitempty"`
	Client DropBackend `toml:"client"`
}

type DropBackend struct {
	Type string `toml:"type"`

	Endpoint  string `toml:"endpoint,omitempty"`
	Region    string `toml:"region,omitempty"`
	Bucket    string `toml:"bucket,omitempty"`
	ObjectKey string `toml:"object_key,omitempty"`
	AccessKey string `toml:"access_key,omitempty"`
	SecretKey string `toml:"secret_key,omitempty"`
	Secure    *bool  `toml:"secure,omitempty"`

	URL      string `toml:"url,omitempty"`
	Username string `toml:"username,omitempty"`
	Password string `toml:"password,omitempty"`

	Path string `toml:"path,omitempty"`
}

func (c Config) ReadDrop() DropBackend {
	if c.Drop.Admin.Type != "" {
		return c.Drop.Admin
	}
	return c.Drop.Client
}

type SyncConfig struct {
	Interval OptionalDuration `toml:"interval,omitempty"`
	Cache    string           `toml:"cache,omitempty"`
	PIDFile  string           `toml:"pid_file,omitempty"`
}

type ObserveConfig struct {
	Enabled         bool             `toml:"enabled,omitempty"`
	HandshakeFresh  OptionalDuration `toml:"handshake_fresh,omitempty"`
	RefreshInterval OptionalDuration `toml:"refresh_interval,omitempty"`
}

// DiscoveryConfig governs LAN peer discovery via multicast beacons.
// See spec/lan-discovery.md.
type DiscoveryConfig struct {
	Enabled        *bool            `toml:"enabled,omitempty"`
	MulticastIPv4  string           `toml:"multicast_ipv4,omitempty"`
	MulticastIPv6  string           `toml:"multicast_ipv6,omitempty"`
	BeaconInterval OptionalDuration `toml:"beacon_interval,omitempty"`
	BeaconTTL      OptionalDuration `toml:"beacon_ttl,omitempty"`
}

// IsEnabled reports whether LAN discovery should run. Discovery defaults to
// enabled when the [discovery] section is absent or omits the field.
func (d DiscoveryConfig) IsEnabled() bool {
	if d.Enabled == nil {
		return true
	}
	return *d.Enabled
}

type OptionalDuration struct {
	Duration time.Duration
	Set      bool
}

func NewDuration(d time.Duration) OptionalDuration {
	return OptionalDuration{Duration: d, Set: true}
}

func (d *OptionalDuration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", string(text), err)
	}
	d.Duration = parsed
	d.Set = true
	return nil
}

func (d OptionalDuration) MarshalText() ([]byte, error) {
	if !d.Set {
		return []byte("0s"), nil
	}
	return []byte(d.Duration.String()), nil
}

func (d OptionalDuration) IsZero() bool {
	return !d.Set
}

func (d OptionalDuration) Or(defaultValue time.Duration) time.Duration {
	if !d.Set {
		return defaultValue
	}
	return d.Duration
}

func (c DropBackend) S3Secure() bool {
	if c.Secure == nil {
		return true
	}
	return *c.Secure
}

func SourcePath(cachePath string) string {
	return filepath.Join(filepath.Dir(cachePath), "directory-source.bin")
}

func StatePath(cachePath string) string {
	return filepath.Join(filepath.Dir(cachePath), "state.json")
}

func SerialPath(cachePath string) string {
	return filepath.Join(filepath.Dir(cachePath), "cache.serial")
}

func DiscoveryStatePath(cachePath string) string {
	return filepath.Join(filepath.Dir(cachePath), "discovery.json")
}
