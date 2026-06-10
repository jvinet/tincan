package cli

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/jvinet/tincan/internal/bootstrap"
	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/drop"
)

func loadConfig(g *Globals) (*config.Config, error) {
	cfg, err := config.Load(g.Config)
	if err != nil {
		return nil, err
	}
	if st, statErr := os.Stat(g.Config); statErr == nil && st.Mode().Perm() != 0o600 {
		newPrinter(os.Stderr).warn("config file should be mode 0600 (path: %s, mode: %s)", g.Config, st.Mode().Perm())
	}
	return cfg, nil
}

func loadAdminDrop(cfg *config.Config) (drop.Drop, error) {
	if cfg.Drop.Admin.Type == "" {
		return nil, fmt.Errorf("[drop.admin] is required for this command")
	}
	return drop.New(cfg.Drop.Admin)
}

func loadReadDrop(cfg *config.Config) (drop.Drop, error) {
	return drop.New(cfg.ReadDrop())
}

func fetchDirectory(ctx context.Context, cfg *config.Config, d drop.Drop) (directory.Directory, error) {
	blob, err := d.Get(ctx)
	if err != nil {
		return directory.Directory{}, err
	}
	dir, _, err := directory.Open(blob, cfg.Directory.NetworkIdentity, cfg.Directory.PublisherPubKey)
	if err != nil {
		return directory.Directory{}, err
	}
	return dir, nil
}

func fetchAdminDirectory(ctx context.Context, cfg *config.Config, d drop.Drop) (directory.Directory, error) {
	dir, err := fetchDirectory(ctx, cfg, d)
	if err == nil {
		return dir, nil
	}
	newPrinter(os.Stderr).fail("failed to fetch current directory from drop, trying local source; %v", err)
	if source, sourceErr := cache.ReadSource(cfg.Sync.StateDir); sourceErr == nil {
		return source, nil
	}
	if cached, _, cacheErr := cache.Read(cfg.Sync.StateDir); cacheErr == nil {
		return cached, nil
	}
	return directory.Directory{}, err
}

// reconcilePublishSerial adopts the remote directory's serial when it is
// ahead of the local working copy, so the caller's subsequent bump always
// yields a serial that has never been published. When the remote cannot be
// read, the local copy may be behind the drop (an observation republish from
// the daemon, a restore from backup), and bumping it would sign a second,
// different payload under an already-used serial — anyone holding both
// signed blobs could then flip clients between the two states forever.
// Refuse in that case unless forced. A missing remote object is the normal
// first-publish case and proceeds.
func reconcilePublishSerial(source *directory.Directory, remote directory.Directory, fetchErr error, force bool) error {
	switch {
	case fetchErr == nil:
		if remote.Serial >= source.Serial {
			source.Serial = remote.Serial
		}
		return nil
	case errors.Is(fetchErr, drop.ErrNotFound):
		return nil
	case force:
		return nil
	default:
		return fmt.Errorf("cannot fetch the published directory before publishing (%v); the local working copy may be behind it, and re-publishing could reuse an already-published serial — fix the drop or pass --force", fetchErr)
	}
}

func publishDirectory(ctx context.Context, cfg *config.Config, d drop.Drop, dir directory.Directory, writeSource bool) error {
	blob, err := directory.Seal(dir, cfg.Directory.PublisherKey)
	if err != nil {
		return err
	}
	if err := d.Put(ctx, blob); err != nil {
		return err
	}
	if err := cache.Write(cfg.Sync.StateDir, dir, ""); err != nil {
		return err
	}
	if writeSource {
		if err := cache.WriteSource(cfg.Sync.StateDir, dir); err != nil {
			return err
		}
	}
	if err := bootstrap.Write(bootstrap.DefaultPath(cfg.Sync.StateDir), bootstrap.Network(cfg, dir.Serial)); err != nil {
		return err
	}
	return nil
}

func bumpDirectory(dir *directory.Directory) error {
	if dir.Serial == math.MaxUint64 {
		return errors.New("directory serial overflow")
	}
	dir.Serial++
	dir.CreatedAt = directory.Stamp()
	return nil
}

func findSelf(cfg *config.Config, dir directory.Directory) (directory.Node, error) {
	for _, node := range dir.Nodes {
		if node.PublicKey == cfg.Wireguard.PublicKey {
			return node, nil
		}
	}
	return directory.Node{}, fmt.Errorf("local WireGuard public key is not present in directory")
}

func nodeByName(dir directory.Directory, name string) (directory.Node, int, bool) {
	for i, node := range dir.Nodes {
		if node.Name == name {
			return node, i, true
		}
	}
	return directory.Node{}, -1, false
}

func takenIPs(dir directory.Directory) []string {
	ips := make([]string, 0, len(dir.Nodes))
	for _, node := range dir.Nodes {
		ips = append(ips, node.TunnelIP)
	}
	return ips
}

func configExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func boolPtr(b bool) *bool { return &b }

// saveConfig writes the generated config either in full (every applicable
// section and field at its default) or minimal (only the fields explicitly
// set, which are the ones likely or required to be changed).
func saveConfig(path string, cfg config.Config, full bool) error {
	if full {
		return config.Save(path, cfg)
	}
	return config.SaveMinimal(path, cfg)
}

func listenPortFromEndpoint(endpoint string) (int, error) {
	if endpoint == "" {
		return 0, nil
	}
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, fmt.Errorf("endpoint must be host:port: %w", err)
	}
	parsed, err := strconv.Atoi(port)
	if err != nil || parsed <= 0 || parsed > 65535 {
		return 0, fmt.Errorf("endpoint port %q is invalid", port)
	}
	return parsed, nil
}

func trimSecret(s string) string {
	return strings.TrimSpace(s)
}
