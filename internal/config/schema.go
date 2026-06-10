package config

import (
	"fmt"
	"path/filepath"
	"time"
)

const (
	DefaultConfigPath = "/etc/tincan/config.toml"
	DefaultStateDir   = "/var/lib/tincan"
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
	Sync      SyncConfig      `toml:"sync,omitempty"`
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
	// NetworkIdentity is this node's own age secret (AGE-SECRET-KEY-1…), unique
	// per node — it decrypts directories sealed to the node's recipient. The
	// field name is historical (it was a single shared secret before schema v2).
	NetworkIdentity string `toml:"network_identity"`
	PublisherPubKey string `toml:"publisher_pubkey"`
	PublisherKey    string `toml:"publisher_key,omitempty"`
}

type DropConfig struct {
	Admin  DropBackend `toml:"admin,omitempty"`
	Client DropBackend `toml:"client"`
}

// The json tags mirror the toml names (and all carry omitempty) so the bootstrap
// file written by `init`/`add-node` stays compact — only the fields a given drop
// type actually uses are emitted, with the same key names as the [drop] config.
type DropBackend struct {
	Type string `toml:"type" json:"type"`

	Endpoint  string `toml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Region    string `toml:"region,omitempty" json:"region,omitempty"`
	Bucket    string `toml:"bucket,omitempty" json:"bucket,omitempty"`
	ObjectKey string `toml:"object_key,omitempty" json:"object_key,omitempty"`
	AccessKey string `toml:"access_key,omitempty" json:"access_key,omitempty"`
	SecretKey string `toml:"secret_key,omitempty" json:"secret_key,omitempty"`
	TLS       *bool  `toml:"tls,omitempty" json:"tls,omitempty"`

	URL      string `toml:"url,omitempty" json:"url,omitempty"`
	Username string `toml:"username,omitempty" json:"username,omitempty"`
	Password string `toml:"password,omitempty" json:"password,omitempty"`

	Path string `toml:"path,omitempty" json:"path,omitempty"`

	// DNS-specific fields. Provider and APIToken are needed only on the write
	// (admin) side; clients read the zone with a plain DNS lookup using just
	// Zone and RecordName.
	Provider   string `toml:"provider,omitempty" json:"provider,omitempty"`
	Zone       string `toml:"zone,omitempty" json:"zone,omitempty"`
	RecordName string `toml:"record_name,omitempty" json:"record_name,omitempty"`
	APIToken   string `toml:"api_token,omitempty" json:"api_token,omitempty"`
	TTL        int    `toml:"ttl,omitempty" json:"ttl,omitempty"`
	Resolver   string `toml:"resolver,omitempty" json:"resolver,omitempty"`
}

func (c Config) ReadDrop() DropBackend {
	if c.Drop.Admin.Type != "" {
		return c.Drop.Admin
	}
	return c.Drop.Client
}

type SyncConfig struct {
	Interval OptionalDuration `toml:"interval,omitempty"`
	// StateDir is the directory that houses the local cache plus its sibling
	// state files (cache.serial, state.json, discovery.json, and the admin-only
	// directory-source.bin / netboot.json). See the Path helpers below.
	StateDir string `toml:"state_dir,omitempty"`
	PIDFile  string `toml:"pid_file,omitempty"`
}

type ObserveConfig struct {
	Enabled        *bool            `toml:"enabled,omitempty"`
	HandshakeFresh OptionalDuration `toml:"handshake_fresh,omitempty"`
	// RefreshInterval is deprecated and ignored. The admin no longer
	// periodically re-stamps ObservedAt: an unchanged observed endpoint is
	// left untouched, and clients trust it for as long as it stays published.
	// The field is retained so existing configs that set it still load (the
	// decoder rejects unknown keys); new configs omit it.
	RefreshInterval OptionalDuration `toml:"refresh_interval,omitempty"`
}

// IsEnabled reports whether the admin should observe peer endpoints. It defaults
// to on when the [observe] section is absent or omits the field, so a freshly
// initialized admin learns NAT'd peer endpoints without extra configuration.
// Only admin nodes consult this (see the call site in `up`); a non-admin that
// leaves it unset is never asked to observe.
func (o ObserveConfig) IsEnabled() bool {
	return o.Enabled == nil || *o.Enabled
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

// S3UseTLS reports whether the s3 client should connect over HTTPS. Defaults to
// true when the tls field is unset.
func (c DropBackend) S3UseTLS() bool {
	if c.TLS == nil {
		return true
	}
	return *c.TLS
}

// The following helpers map a node's state directory to the individual files
// it holds. Keeping the layout in one place is why the config records a
// directory (state_dir) rather than a bare cache file path.

func CachePath(stateDir string) string {
	return filepath.Join(stateDir, "cache.bin")
}

func SourcePath(stateDir string) string {
	return filepath.Join(stateDir, "directory-source.bin")
}

func StatePath(stateDir string) string {
	return filepath.Join(stateDir, "state.json")
}

func SerialPath(stateDir string) string {
	return filepath.Join(stateDir, "cache.serial")
}

func DiscoveryStatePath(stateDir string) string {
	return filepath.Join(stateDir, "discovery.json")
}
