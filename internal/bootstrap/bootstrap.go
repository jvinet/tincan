package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/renameio/v2"
	"github.com/jvinet/tincan/internal/config"
)

// SchemaVersion 2 dropped the shared network identity (now per-node) and added
// the node's age identity to the node block. v1 bootstraps carried the
// defunct shared secret and are rejected.
const SchemaVersion = 2

type Bootstrap struct {
	SchemaVersion int       `json:"schema_version"`
	Directory     Directory `json:"directory"`
	// Serial is the directory serial current when the bootstrap was written.
	// `join` seeds the new node's rollback high-water mark with it, so even
	// the node's first sync refuses a directory older than its enrollment.
	Serial uint64             `json:"serial,omitempty"`
	Drop   config.DropBackend `json:"drop"`
	Node   *Node              `json:"node,omitempty"`
}

type Directory struct {
	PublisherPubKey string `json:"publisher_pubkey"`
}

type Node struct {
	Name     string `json:"name"`
	TunnelIP string `json:"tunnel_ip"`
	// ListenPort is the WireGuard listen port for this node, taken from the
	// port of its published endpoint. Peers reach the node there, so it must
	// bind it; `join` copies it into the client config. Omitted (0) for NAT'd
	// nodes without a published endpoint, which bind an ephemeral port.
	ListenPort int    `json:"listen_port,omitempty"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key,omitempty"`
	// AgeIdentity is this node's age secret (AGE-SECRET-KEY-1…). It decrypts
	// the directory and is unique per node, so it is as sensitive as the
	// WireGuard private key. Present when the admin generated the node's keys.
	AgeIdentity string `json:"age_identity,omitempty"`
}

func Network(cfg *config.Config, serial uint64) Bootstrap {
	return Bootstrap{
		SchemaVersion: SchemaVersion,
		Directory: Directory{
			PublisherPubKey: cfg.Directory.PublisherPubKey,
		},
		Serial: serial,
		Drop:   cfg.Drop.Client,
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
