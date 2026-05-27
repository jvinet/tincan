package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/drop"
)

type SyncCmd struct{}

func (c *SyncCmd) Run(ctx context.Context, g *Globals) error {
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	res, err := runSyncOnce(ctx, cfg, 30*time.Second)
	if err != nil {
		return err
	}
	p := newPrinter(os.Stdout)
	source := "drop"
	if res.FromCache {
		source = "local cache"
	}
	p.headline("synced from %s (serial: %d)", source, res.Serial)
	return nil
}

type syncResult struct {
	Serial    uint64
	FromCache bool
	Directory directory.Directory
}

func runSyncOnce(ctx context.Context, cfg *config.Config, timeout time.Duration) (syncResult, error) {
	d, err := loadDrop(cfg)
	if err != nil {
		return syncResult{}, err
	}
	dir, fromCache, err := fetchSyncDirectory(ctx, cfg, d, timeout)
	if err != nil {
		return syncResult{}, err
	}
	if err := cache.Write(cfg.Sync.Cache, dir, ""); err != nil {
		return syncResult{}, err
	}
	return syncResult{Serial: dir.Serial, FromCache: fromCache, Directory: dir}, nil
}

func fetchSyncDirectory(ctx context.Context, cfg *config.Config, d drop.Drop, timeout time.Duration) (directory.Directory, bool, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	blob, err := d.Get(fetchCtx)
	if err != nil {
		dir, _, cacheErr := cache.Read(cfg.Sync.Cache)
		if cacheErr != nil {
			return directory.Directory{}, false, fmt.Errorf("drop fetch failed (%v) and cache unavailable (%v)", err, cacheErr)
		}
		return dir, true, nil
	}
	dir, _, err := directory.Open(blob, cfg.Directory.NetworkIdentity, cfg.Directory.PublisherPubKey)
	if err != nil {
		return directory.Directory{}, false, err
	}
	if cachedSerial, err := cache.ReadSerial(cfg.Sync.Cache); err == nil && directory.IsRollback(dir.Serial, cachedSerial) {
		return directory.Directory{}, false, fmt.Errorf("stale serial %d is older than cached serial %d", dir.Serial, cachedSerial)
	}
	return dir, false, nil
}
