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
	"time"

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
	if source, sourceErr := cache.ReadSource(cfg.Sync.Cache); sourceErr == nil {
		return source, nil
	}
	if cached, _, cacheErr := cache.Read(cfg.Sync.Cache); cacheErr == nil {
		return cached, nil
	}
	return directory.Directory{}, err
}

func publishDirectory(ctx context.Context, cfg *config.Config, d drop.Drop, dir directory.Directory, writeSource bool) error {
	blob, err := directory.Seal(dir, cfg.Directory.NetworkIdentity, cfg.Directory.PublisherKey)
	if err != nil {
		return err
	}
	if err := d.Put(ctx, blob); err != nil {
		return err
	}
	if err := cache.Write(cfg.Sync.Cache, dir, ""); err != nil {
		return err
	}
	if writeSource {
		if err := cache.WriteSource(cfg.Sync.Cache, dir); err != nil {
			return err
		}
	}
	if err := bootstrap.Write(bootstrap.DefaultPath(cfg.Sync.Cache), bootstrap.Network(cfg)); err != nil {
		return err
	}
	return nil
}

func bumpDirectory(dir *directory.Directory) error {
	if dir.Serial == math.MaxUint64 {
		return errors.New("directory serial overflow")
	}
	dir.Serial++
	dir.CreatedAt = time.Now().UTC()
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
