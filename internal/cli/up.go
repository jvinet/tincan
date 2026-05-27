package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/daemon"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/wg"
)

type UpCmd struct {
	NoSync bool `name:"no-sync" help:"Skip syncing from the dead-drop; apply the local cache as-is."`
	Daemon bool `help:"Fork into the background and continuously sync and apply."`
}

func (c *UpCmd) Run(ctx context.Context, g *Globals) error {
	if daemonConfig := os.Getenv(daemon.EnvConfig); daemonConfig != "" {
		g.Config = daemonConfig
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
		p := newPrinter(os.Stdout)
		p.headline("started tincan daemon")
		p.blank()
		p.pairs(kv("pid", fmt.Sprintf("%d", pid)))
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
	return runUpOnce(ctx, cfg, c.NoSync, newPrinter(os.Stdout))
}

func runUpOnce(ctx context.Context, cfg *config.Config, noSync bool, p *printer) error {
	var dir directory.Directory
	if noSync {
		cached, _, err := cache.Read(cfg.Sync.Cache)
		if err != nil {
			return fmt.Errorf("read cache: %w", err)
		}
		dir = cached
	} else {
		res, err := runSyncOnce(ctx, cfg, 30*time.Second)
		if err != nil {
			return err
		}
		source := "drop"
		if res.FromCache {
			source = "local cache"
		}
		p.headline("synced from %s (serial: %d)", source, res.Serial)
		dir = res.Directory
	}
	self, err := findSelf(cfg, dir)
	if err != nil {
		return err
	}
	manager, err := wg.NewManager(cfg.Wireguard)
	if err != nil {
		return err
	}
	if err := manager.Up(); err != nil {
		return err
	}
	p.headline("bringing up interface %s", cfg.Wireguard.Interface)
	if err := manager.Apply(self, dir); err != nil {
		return err
	}
	p.headline("setting IP address: %s", tunnelDisplay(self.TunnelIP, dir.NetworkCIDR))
	return nil
}

func tunnelDisplay(tunnelIP, networkCIDR string) string {
	_, ipnet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return tunnelIP
	}
	ones, _ := ipnet.Mask.Size()
	return fmt.Sprintf("%s/%d", tunnelIP, ones)
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
			if err := runDaemonIteration(ctx, cfg, timeout); err != nil {
				slog.Error("daemon iteration failed", "error", err)
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
				slog.Info("received SIGHUP, reloading config and reconciling")
				continue
			case syscall.SIGTERM, syscall.SIGINT:
				slog.Info("received shutdown signal", "signal", sig.String())
				return nil
			}
		case <-timer.C:
		}
	}
}

func runDaemonIteration(ctx context.Context, cfg *config.Config, timeout time.Duration) error {
	res, err := runSyncOnce(ctx, cfg, timeout)
	if err != nil {
		return err
	}
	if res.FromCache {
		slog.Info("synced from local cache", "serial", res.Serial)
	} else {
		slog.Info("synced from drop", "serial", res.Serial)
	}
	self, err := findSelf(cfg, res.Directory)
	if err != nil {
		return err
	}
	manager, err := wg.NewManager(cfg.Wireguard)
	if err != nil {
		return err
	}
	return manager.Ensure(self, res.Directory)
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
