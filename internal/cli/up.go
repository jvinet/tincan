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

	"github.com/jvinet/tincan/internal/admin"
	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/daemon"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/relay"
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
			slog.Error("daemon start failed", "error", err)
			return err
		}
		slog.Info("daemon started", "pid", pid, "config", g.Config)
		p := newPrinter(os.Stdout)
		p.headline("started tincan daemon (pid: %d)", pid)
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
	slog.Info("up starting", "no_sync", noSync, "interface", cfg.Wireguard.Interface)
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
			slog.Error("sync failed during up", "error", err)
			return err
		}
		source := "drop"
		if res.FromCache {
			source = "local cache"
		}
		slog.Info("synced", "source", source, "serial", res.Serial)
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
	if err := manager.Apply(self, dir, nil); err != nil {
		slog.Error("apply failed", "error", err)
		return err
	}
	slog.Info("up complete", "interface", cfg.Wireguard.Interface, "tunnel_ip", self.TunnelIP, "peers", len(dir.Nodes)-1)
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
	pout := newPrinter(os.Stdout)
	perr := newPrinter(os.Stderr)

	controller := relay.NewController(relay.Config{})
	wakeCh := make(chan string, 1)

	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	startNetworkWatcher(watchCtx, configPath, controller, wakeCh, perr)
	startAdminPreflight(configPath, pout)

	slog.Info("daemon loop started", "pid", os.Getpid(), "config", configPath)
	prevModes := map[string]relay.Mode{}
	for {
		cfg, err := config.Load(configPath)
		if err != nil {
			slog.Error("config load failed", "error", err, "path", configPath)
			perr.fail("failed to load config; %v", err)
		} else {
			timeout := iterationTimeout(cfg.Sync.Interval.Or(config.DefaultInterval))
			if err := runDaemonIteration(ctx, cfg, timeout, pout, controller, prevModes); err != nil {
				slog.Warn("daemon iteration failed", "error", err)
				perr.fail("daemon iteration failed; %v", err)
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
			slog.Info("daemon loop exiting", "reason", "context canceled")
			return ctx.Err()
		case sig := <-sigCh:
			if !timer.Stop() {
				<-timer.C
			}
			switch sig {
			case syscall.SIGHUP:
				slog.Info("received SIGHUP, reloading config and reconciling")
				pout.hint("received SIGHUP, reloading config and reconciling")
				continue
			case syscall.SIGTERM, syscall.SIGINT:
				slog.Info("received shutdown signal", "signal", sig.String())
				pout.hint("received shutdown signal (%s)", sig.String())
				return nil
			}
		case reason := <-wakeCh:
			if !timer.Stop() {
				<-timer.C
			}
			slog.Info("received wake, reconciling", "reason", reason)
			pout.hint("received wake (%s), reconciling", reason)
			continue
		case <-timer.C:
		}
	}
}

func runDaemonIteration(ctx context.Context, cfg *config.Config, timeout time.Duration, p *printer, controller *relay.Controller, prevModes map[string]relay.Mode) error {
	res, err := runSyncOnce(ctx, cfg, timeout)
	if err != nil {
		return err
	}
	source := "drop"
	if res.FromCache {
		source = "local cache"
	}
	slog.Info("synced", "source", source, "serial", res.Serial)
	p.headline("synced from %s (serial: %d)", source, res.Serial)
	self, err := findSelf(cfg, res.Directory)
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
	peers, err := manager.Peers()
	if err != nil {
		// Pre-existing interface state isn't a hard failure on the very first
		// iteration; treat the snapshot as empty and continue.
		peers = nil
	}
	decision := controller.Update(self, res.Directory, peers, time.Now())
	logRelayTransitions(p, res.Directory, decision, prevModes)
	if err := manager.Apply(self, res.Directory, decision.Relayed); err != nil {
		return err
	}
	slog.Debug("applied directory", "serial", res.Serial, "peers", len(res.Directory.Nodes)-1, "relayed", len(decision.Relayed))
	if cfg.Observe.Enabled {
		if err := runAdminObservation(ctx, cfg, manager, res.Serial, p); err != nil {
			return err
		}
	}
	return nil
}

func logRelayTransitions(p *printer, dir directory.Directory, decision relay.Decision, prev map[string]relay.Mode) {
	if len(decision.PeerStates) == 0 {
		return
	}
	nameByKey := make(map[string]string, len(dir.Nodes))
	for _, node := range dir.Nodes {
		nameByKey[node.PublicKey] = node.Name
	}
	for key, state := range decision.PeerStates {
		old, hadOld := prev[key]
		if hadOld && old == state.Mode {
			continue
		}
		name := nameByKey[key]
		if name == "" {
			name = key
		}
		switch state.Mode {
		case relay.ModeRelayed:
			via := ""
			if decision.RelayTarget != nil {
				via = decision.RelayTarget.Name
			}
			slog.Info("relay transition", "peer", name, "mode", "relayed", "via", via)
			p.headline("relay: peer %q now routed via %s", name, via)
		case relay.ModeDirect:
			if hadOld && old == relay.ModeRelayed {
				slog.Info("relay transition", "peer", name, "mode", "direct")
				p.headline("relay: peer %q back to direct", name)
			}
		}
		prev[key] = state.Mode
	}
	// Drop entries for peers no longer in the decision (removed from directory).
	for key := range prev {
		if _, still := decision.PeerStates[key]; !still {
			delete(prev, key)
		}
	}
}

func runAdminObservation(ctx context.Context, cfg *config.Config, manager *wg.Manager, syncedSerial uint64, p *printer) error {
	if err := config.RequireAdmin(*cfg); err != nil {
		return fmt.Errorf("[observe].enabled requires admin role: %w", err)
	}
	source, err := cache.ReadSource(cfg.Sync.Cache)
	if err != nil {
		return fmt.Errorf("read source directory: %w", err)
	}
	if syncedSerial > source.Serial {
		source.Serial = syncedSerial
	}
	peers, err := manager.Peers()
	if err != nil {
		return err
	}
	handshakeFresh := cfg.Observe.HandshakeFresh.Or(admin.DefaultHandshakeFresh)
	refreshInterval := cfg.Observe.RefreshInterval.Or(admin.DefaultRefreshInterval)
	updated, changed := admin.MergeObservations(source, peers, time.Now(), handshakeFresh, refreshInterval)
	if !changed {
		return nil
	}
	if err := bumpDirectory(&updated); err != nil {
		return err
	}
	d, err := loadAdminDrop(cfg)
	if err != nil {
		return err
	}
	if err := publishDirectory(ctx, cfg, d, updated, true); err != nil {
		return err
	}
	slog.Info("republished after endpoint observation", "serial", updated.Serial)
	p.headline("republished after endpoint observation (serial: %d)", updated.Serial)
	return nil
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
