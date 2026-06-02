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
	newPrinter(os.Stdout).reportSync(res)
	return nil
}

type syncResult struct {
	Serial    uint64
	FromCache bool
	// StaleErr is the drop error that forced a fall back to the local cache. It
	// is non-nil exactly when FromCache is true, so callers can report why they
	// are serving a cached (and possibly stale) directory instead of failing.
	StaleErr  error
	Directory directory.Directory
}

// syncSource describes where a syncResult's directory came from.
func syncSource(res syncResult) string {
	if res.FromCache {
		return "local cache"
	}
	return "drop"
}

// reportSync prints the sync outcome and, when the drop was unreachable and a
// stale cached directory is being served instead, warns with the underlying
// drop error. sync previously swallowed that error behind a success message.
func (p *printer) reportSync(res syncResult) {
	p.headline("synced from %s (serial: %d)", syncSource(res), res.Serial)
	if res.FromCache && res.StaleErr != nil {
		p.warn("drop unreachable (%v); serving cached serial %d", res.StaleErr, res.Serial)
	}
}

func runSyncOnce(ctx context.Context, cfg *config.Config, timeout time.Duration) (syncResult, error) {
	d, err := loadReadDrop(cfg)
	if err != nil {
		return syncResult{}, err
	}
	dir, fromCache, dropErr, err := fetchSyncDirectory(ctx, cfg, d, timeout)
	if err != nil {
		return syncResult{}, err
	}
	if err := cache.Write(cfg.Sync.StateDir, dir, ""); err != nil {
		return syncResult{}, err
	}
	return syncResult{Serial: dir.Serial, FromCache: fromCache, StaleErr: dropErr, Directory: dir}, nil
}

// fetchSyncDirectory loads the directory from the drop, falling back to the
// local cache when the drop is unreachable.
//
// It returns the directory; whether it came from the cache; the non-fatal
// dropErr that triggered the fallback (non-nil exactly when fromCache is true);
// and a fatal err. A fatal err means neither the drop nor the cache could
// satisfy the request, or the fetched directory was invalid. Callers should
// surface dropErr but may continue serving the cached directory.
func fetchSyncDirectory(ctx context.Context, cfg *config.Config, d drop.Drop, timeout time.Duration) (directory.Directory, bool, error, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	blob, dropErr := d.Get(fetchCtx)
	if dropErr != nil {
		dir, _, cacheErr := cache.Read(cfg.Sync.StateDir)
		if cacheErr != nil {
			return directory.Directory{}, false, dropErr, fmt.Errorf("drop fetch failed (%v) and cache unavailable (%v)", dropErr, cacheErr)
		}
		return dir, true, dropErr, nil
	}
	dir, _, err := directory.Open(blob, cfg.Directory.NetworkIdentity, cfg.Directory.PublisherPubKey)
	if err != nil {
		return directory.Directory{}, false, nil, err
	}
	if cachedSerial, err := cache.ReadSerial(cfg.Sync.StateDir); err == nil && directory.IsRollback(dir.Serial, cachedSerial) {
		return directory.Directory{}, false, nil, fmt.Errorf("stale serial %d is older than cached serial %d", dir.Serial, cachedSerial)
	}
	return dir, false, nil, nil
}
