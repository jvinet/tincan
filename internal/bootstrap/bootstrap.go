package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/renameio/v2"
	"github.com/jvinet/tincan/internal/config"
)

const SchemaVersion = 1

type Bootstrap struct {
	SchemaVersion int                `json:"schema_version"`
	Directory     Directory          `json:"directory"`
	Drop          config.DropBackend `json:"drop"`
	Node          *Node              `json:"node,omitempty"`
}

type Directory struct {
	NetworkIdentity string `json:"network_identity"`
	PublisherPubKey string `json:"publisher_pubkey"`
}

type Node struct {
	Name       string `json:"name"`
	TunnelIP   string `json:"tunnel_ip"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key,omitempty"`
}

func Network(cfg *config.Config) Bootstrap {
	return Bootstrap{
		SchemaVersion: SchemaVersion,
		Directory: Directory{
			NetworkIdentity: cfg.Directory.NetworkIdentity,
			PublisherPubKey: cfg.Directory.PublisherPubKey,
		},
		Drop: cfg.Drop.Client,
	}
}

func WithNode(base Bootstrap, node Node) Bootstrap {
	base.Node = &node
	return base
}

func DefaultPath(stateDir string) string {
	return filepath.Join(stateDir, "netboot.json")
}

func Write(path string, b Bootstrap) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bootstrap: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create bootstrap directory: %w", err)
	}
	if err := renameio.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write bootstrap: %w", err)
	}
	return nil
}

func Read(path string) (Bootstrap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("read bootstrap: %w", err)
	}
	var b Bootstrap
	if err := json.Unmarshal(data, &b); err != nil {
		return Bootstrap{}, fmt.Errorf("decode bootstrap: %w", err)
	}
	if b.SchemaVersion != SchemaVersion {
		return Bootstrap{}, fmt.Errorf("bootstrap schema version %d not supported (expected %d)", b.SchemaVersion, SchemaVersion)
	}
	return b, nil
}
