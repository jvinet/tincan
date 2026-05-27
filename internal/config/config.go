package config

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/renameio/v2"
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
			Cache:    DefaultCachePath,
			PIDFile:  DefaultPIDFile,
		},
	}
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Mode().Perm() != 0o600 {
		slog.Warn("config file should be mode 0600", "path", path, "mode", st.Mode().Perm().String())
	}
	cfg := Default()
	dec := toml.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(false); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func Save(path string, cfg Config) error {
	cfg.ApplyDefaults()
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := renameio.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
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
	if c.Sync.Cache == "" {
		c.Sync.Cache = DefaultCachePath
	}
	if c.Sync.PIDFile == "" {
		c.Sync.PIDFile = DefaultPIDFile
	}
}

func applyBackendDefaults(b *DropBackend) {
	if b.Type == "s3" && b.ObjectKey == "" {
		b.ObjectKey = "directory.bin"
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
		return rejectBackendFields("path", b.Endpoint, b.Region, b.Bucket, b.ObjectKey, b.AccessKey, b.SecretKey, b.URL, b.Username, b.Password)
	case "http":
		if b.URL == "" {
			return errors.New("url is required for http drops")
		}
		return rejectBackendFields("url/username/password", b.Endpoint, b.Region, b.Bucket, b.ObjectKey, b.AccessKey, b.SecretKey, b.Path)
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
		return rejectBackendFields("endpoint/region/bucket/object_key/access_key/secret_key/secure", b.URL, b.Username, b.Password, b.Path)
	default:
		return fmt.Errorf("unsupported type %q", b.Type)
	}
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
	secure := true
	switch dropType {
	case "s3":
		admin := DropBackend{Type: "s3", Endpoint: "s3.amazonaws.com", Region: "us-east-1", Bucket: "my-tincan-net", ObjectKey: "directory.bin", AccessKey: "admin-access-key", SecretKey: "admin-secret-key", Secure: &secure}
		client := DropBackend{Type: "s3", Endpoint: "s3.amazonaws.com", Region: "us-east-1", Bucket: "my-tincan-net", ObjectKey: "directory.bin", Secure: &secure}
		return DropConfig{Admin: admin, Client: client}
	case "http":
		admin := DropBackend{Type: "file", Path: DefaultStateDir + "/publish/directory.bin"}
		client := DropBackend{Type: "http", URL: "https://example.com/_vpn/directory"}
		return DropConfig{Admin: admin, Client: client}
	case "file":
		b := DropBackend{Type: "file", Path: "/mnt/shared/tincan/directory.bin"}
		return DropConfig{Admin: b, Client: b}
	default:
		b := DropBackend{Type: dropType}
		return DropConfig{Admin: b, Client: b}
	}
}

func SkeletonClientDrop(dropType string) DropConfig {
	full := SkeletonDrop(dropType)
	return DropConfig{Client: full.Client}
}
