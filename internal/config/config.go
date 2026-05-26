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
	if c.Drop.Type == "s3" && c.Drop.ObjectKey == "" {
		c.Drop.ObjectKey = "directory.bin"
	}
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
	return validateDrop(c.Drop)
}

func RequireAdmin(c Config) error {
	if strings.TrimSpace(c.Directory.PublisherKey) == "" {
		return errors.New("admin publisher key is required for this command")
	}
	return keys.ValidateEd25519Pair(c.Directory.PublisherPubKey, c.Directory.PublisherKey)
}

func validateDrop(c DropConfig) error {
	switch c.Type {
	case "file":
		if c.Path == "" {
			return errors.New("[drop].path is required for file drops")
		}
		return reject(c, "path", c.Endpoint, c.Region, c.Bucket, c.ObjectKey, c.AccessKey, c.SecretKey, c.URL, c.Username, c.Password)
	case "http":
		if c.URL == "" {
			return errors.New("[drop].url is required for http drops")
		}
		return reject(c, "url/username/password", c.Endpoint, c.Region, c.Bucket, c.ObjectKey, c.AccessKey, c.SecretKey, c.Path)
	case "s3":
		if c.Endpoint == "" {
			return errors.New("[drop].endpoint is required for s3 drops")
		}
		if c.Bucket == "" {
			return errors.New("[drop].bucket is required for s3 drops")
		}
		if (c.AccessKey == "") != (c.SecretKey == "") {
			return errors.New("[drop].access_key and secret_key must be provided together")
		}
		return reject(c, "endpoint/region/bucket/object_key/access_key/secret_key/secure", c.URL, c.Username, c.Password, c.Path)
	default:
		return fmt.Errorf("unsupported [drop].type %q", c.Type)
	}
}

func reject(_ DropConfig, allowed string, values ...string) error {
	for _, value := range values {
		if value != "" {
			return fmt.Errorf("[drop] contains fields not valid for this type; allowed fields: %s", allowed)
		}
	}
	return nil
}

func SkeletonDrop(dropType string) DropConfig {
	secure := true
	switch dropType {
	case "s3":
		return DropConfig{Type: "s3", Endpoint: "s3.amazonaws.com", Region: "us-east-1", Bucket: "my-tincan-net", ObjectKey: "directory.bin", Secure: &secure}
	case "http":
		return DropConfig{Type: "http", URL: "https://example.com/_vpn/directory"}
	case "file":
		return DropConfig{Type: "file", Path: "/mnt/shared/tincan/directory.bin"}
	default:
		return DropConfig{Type: dropType}
	}
}
