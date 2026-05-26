package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/daemon"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/drop"
	"github.com/jvinet/tincan/internal/wg"
)

type SyncCmd struct {
	Daemon bool `help:"Run as a background daemon."`
	Once   bool `help:"Run one sync iteration and exit."`
}

func (c *SyncCmd) Run(ctx context.Context, g *Globals) error {
	if daemonConfig := os.Getenv(daemon.EnvConfig); daemonConfig != "" {
		g.Config = daemonConfig
	}
	if c.Daemon && c.Once {
		return errors.New("--daemon and --once cannot be used together")
	}
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	if c.Daemon && !daemon.IsChild() {
		pid, err := daemon.Start(cfg.Sync.PIDFile, g.Config)
		if err != nil {
			return err
		}
		fmt.Printf("started tincan daemon with PID %d\n", pid)
		return nil
	}
	if c.Daemon && daemon.IsChild() {
		if err := daemon.BecomeChild(); err != nil {
			return err
		}
		pidFile, err := daemon.AcquirePIDFileRetry(cfg.Sync.PIDFile, os.Getpid(), 2*time.Second)
		if err != nil {
			return err
		}
		defer pidFile.CloseRemove()
		return runDaemonLoop(ctx, g.Config)
	}
	return runSyncOnce(ctx, cfg, 30*time.Second)
}

func runDaemonLoop(ctx context.Context, configPath string) error {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)
	for {
		cfg, err := config.Load(configPath)
		if err != nil {
			slog.Error("failed to load config", "error", err)
		} else {
			timeout := iterationTimeout(cfg.Sync.Interval.Or(config.DefaultInterval))
			if err := runSyncOnce(ctx, cfg, timeout); err != nil {
				slog.Error("sync iteration failed", "error", err)
			}
		}
		interval := config.DefaultInterval
		if cfg != nil {
			interval = cfg.Sync.Interval.Or(config.DefaultInterval)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case sig := <-sigCh:
			if !timer.Stop() {
				<-timer.C
			}
			switch sig {
			case syscall.SIGHUP:
				slog.Info("received SIGHUP, reloading config and syncing")
				continue
			case syscall.SIGTERM, syscall.SIGINT:
				slog.Info("received shutdown signal", "signal", sig.String())
				return nil
			}
		case <-timer.C:
		}
	}
}

func iterationTimeout(interval time.Duration) time.Duration {
	if interval <= 10*time.Second {
		return 30 * time.Second
	}
	t := interval - 5*time.Second
	if t > time.Minute {
		return time.Minute
	}
	return t
}

func runSyncOnce(ctx context.Context, cfg *config.Config, timeout time.Duration) error {
	d, err := loadDrop(cfg)
	if err != nil {
		return err
	}
	dir, fromCache, err := fetchSyncDirectory(ctx, cfg, d, timeout)
	if err != nil {
		return err
	}
	self, err := findSelf(cfg, dir)
	if err != nil {
		return err
	}
	manager, err := wg.NewManager(cfg.Wireguard)
	if err != nil {
		return err
	}
	if err := manager.Ensure(self, dir); err != nil {
		return err
	}
	if err := cache.Write(cfg.Sync.Cache, dir, ""); err != nil {
		return err
	}
	if fromCache {
		slog.Info("synced from local cache", "serial", dir.Serial)
	} else {
		slog.Info("synced from drop", "serial", dir.Serial)
	}
	return nil
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
