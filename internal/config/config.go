package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/renameio/v2"
	"github.com/jvinet/tincan/internal/dnsprovider"
	"github.com/jvinet/tincan/internal/keys"
	"github.com/pelletier/go-toml/v2"
)

func Default() Config {
	return Config{
		Wireguard: WireguardConfig{
			Interface: DefaultInterface,
			MTU:       DefaultMTU,
		},
		Drop: DropConfig{},
		Sync: SyncConfig{
			Interval: NewDuration(DefaultInterval),
			StateDir: DefaultStateDir,
			PIDFile:  DefaultPIDFile,
		},
		Discovery: DiscoveryConfig{
			MulticastIPv4:  DefaultDiscoveryMulticastIPv4,
			MulticastIPv6:  DefaultDiscoveryMulticastIPv6,
			BeaconInterval: NewDuration(DefaultDiscoveryBeaconInterval),
			BeaconTTL:      NewDuration(DefaultDiscoveryBeaconTTL),
		},
	}
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	cfg := Default()
	dec := toml.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", explainDecodeError(err))
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(false); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// explainDecodeError rewrites go-toml's strict-mode error — whose own message
// is the unhelpful "fields in the document are missing in the target struct" —
// into one that names each offending key and the line it sits on, so an
// operator can jump straight to it (e.g. after a config field is renamed). The
// structured error already carries the full dotted key path and position; we
// just surface them. Any other decode error passes through unchanged.
func explainDecodeError(err error) error {
	var strict *toml.StrictMissingError
	if !errors.As(err, &strict) || len(strict.Errors) == 0 {
		return err
	}
	items := make([]string, len(strict.Errors))
	for i := range strict.Errors {
		e := strict.Errors[i]
		line, _ := e.Position()
		items[i] = fmt.Sprintf("%q at line %d", strings.Join(e.Key(), "."), line)
	}
	if len(items) == 1 {
		return fmt.Errorf("unknown field %s", items[0])
	}
	return fmt.Errorf("unknown fields: %s", strings.Join(items, "; "))
}

// Save writes a complete configuration: every default is materialized so the
// file lists all sections and fields applicable to the node.
func Save(path string, cfg Config) error {
	cfg.ApplyDefaults()
	return writeConfig(path, cfg)
}

// SaveMinimal writes cfg verbatim, without materializing defaults. Fields the
// caller left unset are dropped by the encoder's omitempty handling, so the
// file contains only what was explicitly provided — the fields likely or
// required to be changed. Used by `init`/`join` without --full-config.
func SaveMinimal(path string, cfg Config) error {
	return writeConfig(path, cfg)
}

func writeConfig(path string, cfg Config) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := renameio.WriteFile(path, stripRedundantParentHeaders(buf.Bytes()), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// stripRedundantParentHeaders removes parent table headers like a bare [drop]
// that go-toml v2 emits immediately before [drop.admin] / [drop.client].
// The parent header carries no fields of its own and is implicit in the
// sub-table headers; keeping it just clutters the file.
func stripRedundantParentHeaders(data []byte) []byte {
	lines := bytes.Split(data, []byte("\n"))
	out := make([][]byte, 0, len(lines))
	for i := range lines {
		if isRedundantParentHeader(lines, i) {
			continue
		}
		out = append(out, lines[i])
	}
	return bytes.Join(out, []byte("\n"))
}

func isRedundantParentHeader(lines [][]byte, i int) bool {
	line := bytes.TrimSpace(lines[i])
	if len(line) < 3 || line[0] != '[' || line[len(line)-1] != ']' {
		return false
	}
	inner := line[1 : len(line)-1]
	if bytes.IndexByte(inner, '.') >= 0 {
		return false
	}
	prefix := append([]byte{'['}, inner...)
	prefix = append(prefix, '.')
	for j := i + 1; j < len(lines); j++ {
		next := bytes.TrimSpace(lines[j])
		if len(next) == 0 {
			continue
		}
		return bytes.HasPrefix(next, prefix)
	}
	return false
}

func (c *Config) ApplyDefaults() {
	if c.Wireguard.Interface == "" {
		c.Wireguard.Interface = DefaultInterface
	}
	if c.Wireguard.MTU == 0 {
		c.Wireguard.MTU = DefaultMTU
	}
	applyBackendDefaults(&c.Drop.Admin)
	applyBackendDefaults(&c.Drop.Client)
	if !c.Sync.Interval.Set {
		c.Sync.Interval = NewDuration(DefaultInterval)
	}
	if c.Sync.StateDir == "" {
		c.Sync.StateDir = DefaultStateDir
	}
	if c.Sync.PIDFile == "" {
		c.Sync.PIDFile = DefaultPIDFile
	}
	if c.Discovery.MulticastIPv4 == "" {
		c.Discovery.MulticastIPv4 = DefaultDiscoveryMulticastIPv4
	}
	if c.Discovery.MulticastIPv6 == "" {
		c.Discovery.MulticastIPv6 = DefaultDiscoveryMulticastIPv6
	}
	if !c.Discovery.BeaconInterval.Set {
		c.Discovery.BeaconInterval = NewDuration(DefaultDiscoveryBeaconInterval)
	}
	if !c.Discovery.BeaconTTL.Set {
		c.Discovery.BeaconTTL = NewDuration(DefaultDiscoveryBeaconTTL)
	}
}

func applyBackendDefaults(b *DropBackend) {
	if b.Type == "s3" && b.ObjectKey == "" {
		b.ObjectKey = "directory.bin"
	}
	if b.Type == "dns" {
		if b.RecordName == "" {
			b.RecordName = "_tincan"
		}
		// TTL only governs the records the admin writes, so default it on the
		// write (provider) side only; read-only client configs stay clean.
		if b.Provider != "" && b.TTL == 0 {
			b.TTL = 300
		}
	}
}

func (c Config) Validate(allowIncomplete bool) error {
	if strings.TrimSpace(c.Wireguard.Name) == "" {
		return errors.New("[wireguard].name is required")
	}
	if strings.TrimSpace(c.Wireguard.PrivateKey) == "" {
		return errors.New("[wireguard].private_key is required")
	}
	if strings.TrimSpace(c.Wireguard.PublicKey) == "" {
		return errors.New("[wireguard].public_key is required")
	}
	if _, err := keys.ParseWGPrivate(c.Wireguard.PrivateKey); err != nil {
		return err
	}
	if _, err := keys.ParseWGPublic(c.Wireguard.PublicKey); err != nil {
		return err
	}
	derived, err := keys.PublicKeyFromWGPrivate(c.Wireguard.PrivateKey)
	if err != nil {
		return err
	}
	if derived != c.Wireguard.PublicKey {
		return errors.New("[wireguard].public_key does not match private_key")
	}
	if c.Wireguard.ListenPort < 0 || c.Wireguard.ListenPort > 65535 {
		return errors.New("[wireguard].listen_port must be between 0 and 65535")
	}
	if c.Wireguard.MTU <= 0 {
		return errors.New("[wireguard].mtu must be positive")
	}
	if allowIncomplete {
		return nil
	}
	if strings.TrimSpace(c.Directory.NetworkIdentity) == "" {
		return errors.New("[directory].network_identity is required")
	}
	if _, err := keys.ParseAgeIdentity(c.Directory.NetworkIdentity); err != nil {
		return err
	}
	if strings.TrimSpace(c.Directory.PublisherPubKey) == "" {
		return errors.New("[directory].publisher_pubkey is required")
	}
	if _, err := keys.DecodeEd25519Public(c.Directory.PublisherPubKey); err != nil {
		return err
	}
	if c.Directory.PublisherKey != "" {
		if err := keys.ValidateEd25519Pair(c.Directory.PublisherPubKey, c.Directory.PublisherKey); err != nil {
			return err
		}
	}
	if c.Drop.Admin.Type != "" {
		if err := validateDropBackend(c.Drop.Admin); err != nil {
			return fmt.Errorf("[drop.admin]: %w", err)
		}
	}
	if err := validateDropBackend(c.Drop.Client); err != nil {
		return fmt.Errorf("[drop.client]: %w", err)
	}
	if err := validateDiscovery(c.Discovery); err != nil {
		return fmt.Errorf("[discovery]: %w", err)
	}
	if err := validateDNS(c.DNS); err != nil {
		return fmt.Errorf("[dns]: %w", err)
	}
	return nil
}

func validateDNS(d DNSConfig) error {
	if d.Upstream != "" {
		if err := validateHostPort(d.Upstream); err != nil {
			return fmt.Errorf("upstream: %w", err)
		}
	}
	if d.HostsPath != "" && !filepath.IsAbs(d.HostsPath) {
		return fmt.Errorf("hosts_path %q must be absolute", d.HostsPath)
	}
	return nil
}

// validateHostPort accepts "host" (port 53 implied) or "host:port", the same
// convention the dns drop's resolver field uses.
func validateHostPort(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host, portStr = addr, ""
	}
	if host == "" {
		return fmt.Errorf("%q has empty host", addr)
	}
	if strings.ContainsAny(host, " \t\n") {
		return fmt.Errorf("invalid host in %q", addr)
	}
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port in %q", addr)
		}
	}
	return nil
}

func validateDiscovery(d DiscoveryConfig) error {
	if err := validateMulticastAddr(d.MulticastIPv4, false); err != nil {
		return fmt.Errorf("multicast_ipv4: %w", err)
	}
	if err := validateMulticastAddr(d.MulticastIPv6, true); err != nil {
		return fmt.Errorf("multicast_ipv6: %w", err)
	}
	interval := d.BeaconInterval.Or(DefaultDiscoveryBeaconInterval)
	ttl := d.BeaconTTL.Or(DefaultDiscoveryBeaconTTL)
	if interval <= 0 {
		return errors.New("beacon_interval must be positive")
	}
	if ttl < 2*interval {
		return fmt.Errorf("beacon_ttl (%s) must be at least 2x beacon_interval (%s)", ttl, interval)
	}
	return nil
}

func validateMulticastAddr(addr string, wantV6 bool) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port in %q", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid IP in %q", addr)
	}
	if !ip.IsMulticast() {
		return fmt.Errorf("%s is not a multicast address", host)
	}
	if wantV6 && ip.To4() != nil {
		return fmt.Errorf("%s is not an IPv6 address", host)
	}
	if !wantV6 && ip.To4() == nil {
		return fmt.Errorf("%s is not an IPv4 address", host)
	}
	return nil
}

func RequireAdmin(c Config) error {
	if strings.TrimSpace(c.Directory.PublisherKey) == "" {
		return errors.New("admin publisher key is required for this command")
	}
	if c.Drop.Admin.Type == "" {
		return errors.New("[drop.admin] is required for this command")
	}
	return keys.ValidateEd25519Pair(c.Directory.PublisherPubKey, c.Directory.PublisherKey)
}

func validateDropBackend(b DropBackend) error {
	switch b.Type {
	case "file":
		if b.Path == "" {
			return errors.New("path is required for file drops")
		}
		return rejectBackendFields("path", b.Endpoint, b.Region, b.Bucket, b.ObjectKey, b.AccessKey, b.SecretKey, b.URL, b.Username, b.Password, b.Provider, b.Zone, b.RecordName, b.APIToken, b.AppKey, b.AppSecret, b.ConsumerKey, b.Resolver)
	case "http":
		if b.URL == "" {
			return errors.New("url is required for http drops")
		}
		u, err := url.Parse(b.URL)
		if err != nil {
			return fmt.Errorf("invalid http drop url: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("http drop url must be http or https, got %q", u.Scheme)
		}
		// Basic-auth credentials over cleartext http are broadcast on every
		// poll. The directory blob is encrypted regardless, but the drop
		// credentials must not be. (Loopback is exempt — local MinIO/dev.)
		hasCreds := b.Username != "" || b.Password != "" || u.User != nil
		if hasCreds && u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
			return errors.New("http drop sends credentials in cleartext; use https (or omit credentials)")
		}
		return rejectBackendFields("url/username/password", b.Endpoint, b.Region, b.Bucket, b.ObjectKey, b.AccessKey, b.SecretKey, b.Path, b.Provider, b.Zone, b.RecordName, b.APIToken, b.AppKey, b.AppSecret, b.ConsumerKey, b.Resolver)
	case "s3":
		if b.Endpoint == "" {
			return errors.New("endpoint is required for s3 drops")
		}
		if b.Bucket == "" {
			return errors.New("bucket is required for s3 drops")
		}
		if (b.AccessKey == "") != (b.SecretKey == "") {
			return errors.New("access_key and secret_key must be provided together")
		}
		return rejectBackendFields("endpoint/region/bucket/object_key/access_key/secret_key/tls", b.URL, b.Username, b.Password, b.Path, b.Provider, b.Zone, b.RecordName, b.APIToken, b.AppKey, b.AppSecret, b.ConsumerKey, b.Resolver)
	case "dns":
		if b.Zone == "" {
			return errors.New("zone is required for dns drops")
		}
		switch b.Provider {
		case "":
			// Read-only client side: no write credentials of any kind.
			if b.APIToken != "" || b.AppKey != "" || b.AppSecret != "" || b.ConsumerKey != "" || b.AccessKey != "" || b.SecretKey != "" {
				return errors.New("dns write credentials are set but no provider is configured")
			}
			if b.Endpoint != "" {
				return errors.New("endpoint is only used by the ovh dns provider")
			}
		case "ovh":
			if b.AppKey == "" || b.AppSecret == "" || b.ConsumerKey == "" {
				return errors.New("ovh dns provider requires app_key, app_secret, and consumer_key")
			}
			if b.APIToken != "" {
				return errors.New("api_token is not used by the ovh dns provider; use app_key/app_secret/consumer_key")
			}
			if b.AccessKey != "" || b.SecretKey != "" {
				return errors.New("access_key/secret_key are not used by the ovh dns provider; use app_key/app_secret/consumer_key")
			}
		case "route53":
			if b.AccessKey == "" || b.SecretKey == "" {
				return errors.New("route53 dns provider requires access_key and secret_key")
			}
			if b.APIToken != "" {
				return errors.New("api_token is not used by the route53 dns provider; use access_key/secret_key")
			}
			if b.AppKey != "" || b.AppSecret != "" || b.ConsumerKey != "" {
				return errors.New("app_key/app_secret/consumer_key are only used by the ovh dns provider, not route53")
			}
			if b.Endpoint != "" {
				return errors.New("endpoint is only used by the ovh dns provider, not route53")
			}
		default: // token providers (linode, digitalocean, cloudflare, desec, hetzner)
			if !dnsprovider.Supported(b.Provider) {
				return fmt.Errorf("unsupported dns provider %q", b.Provider)
			}
			if b.APIToken == "" {
				return fmt.Errorf("api_token is required for dns provider %q", b.Provider)
			}
			if b.AppKey != "" || b.AppSecret != "" || b.ConsumerKey != "" {
				return fmt.Errorf("app_key/app_secret/consumer_key are only used by the ovh dns provider, not %q", b.Provider)
			}
			if b.AccessKey != "" || b.SecretKey != "" {
				return fmt.Errorf("access_key/secret_key are only used by the route53 dns provider, not %q", b.Provider)
			}
			if b.Endpoint != "" {
				return fmt.Errorf("endpoint is only used by the ovh dns provider, not %q", b.Provider)
			}
		}
		return rejectBackendFields("provider/zone/record_name/api_token/app_key/app_secret/consumer_key/access_key/secret_key/endpoint/ttl/resolver", b.Region, b.Bucket, b.ObjectKey, b.URL, b.Username, b.Password, b.Path)
	default:
		return fmt.Errorf("unsupported type %q", b.Type)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func rejectBackendFields(allowed string, values ...string) error {
	for _, value := range values {
		if value != "" {
			return fmt.Errorf("contains fields not valid for this type; allowed fields: %s", allowed)
		}
	}
	return nil
}

func SkeletonDrop(dropType string) DropConfig {
	tls := true
	switch dropType {
	case "s3":
		admin := DropBackend{Type: "s3", Endpoint: "s3.amazonaws.com", Region: "us-east-1", Bucket: "my-tincan-net", ObjectKey: "directory.bin", AccessKey: "admin-access-key", SecretKey: "admin-secret-key", TLS: &tls}
		client := DropBackend{Type: "s3", Endpoint: "s3.amazonaws.com", Region: "us-east-1", Bucket: "my-tincan-net", ObjectKey: "directory.bin", TLS: &tls}
		return DropConfig{Admin: admin, Client: client}
	case "http":
		admin := DropBackend{Type: "file", Path: DefaultStateDir + "/publish/directory.bin"}
		client := DropBackend{Type: "http", URL: "https://example.com/_vpn/directory"}
		return DropConfig{Admin: admin, Client: client}
	case "file":
		b := DropBackend{Type: "file", Path: "/mnt/shared/tincan/directory.bin"}
		return DropConfig{Admin: b, Client: b}
	case "dns":
		admin := DropBackend{Type: "dns", Provider: "linode", Zone: "example.com", RecordName: "_tincan", APIToken: "YOUR-LINODE-API-TOKEN", TTL: 300}
		client := DropBackend{Type: "dns", Zone: "example.com", RecordName: "_tincan"}
		return DropConfig{Admin: admin, Client: client}
	default:
		b := DropBackend{Type: dropType}
		return DropConfig{Admin: b, Client: b}
	}
}

func SkeletonClientDrop(dropType string) DropConfig {
	full := SkeletonDrop(dropType)
	return DropConfig{Client: full.Client}
}
