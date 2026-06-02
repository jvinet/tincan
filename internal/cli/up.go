package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jvinet/tincan/internal/admin"
	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/daemon"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/discovery"
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
	if err := manager.Apply(self, dir, nil, nil); err != nil {
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
	startNetworkWatcher(watchCtx, configPath, wakeCh, perr)
	startAdminPreflight(configPath, pout)

	var dirHolder atomic.Pointer[directory.Directory]
	dirSource := func() directory.Directory {
		if p := dirHolder.Load(); p != nil {
			return *p
		}
		return directory.Directory{}
	}
	lanStore := startDiscovery(watchCtx, configPath, dirSource, wakeCh, perr)

	slog.Info("daemon loop started", "pid", os.Getpid(), "config", configPath)
	prevModes := map[string]relay.Mode{}
	for {
		cfg, err := config.Load(configPath)
		if err != nil {
			slog.Error("config load failed", "error", err, "path", configPath)
			perr.fail("failed to load config; %v", err)
		} else {
			timeout := iterationTimeout(cfg.Sync.Interval.Or(config.DefaultInterval))
			if err := runDaemonIteration(ctx, cfg, timeout, pout, controller, prevModes, lanStore, &dirHolder); err != nil {
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

func runDaemonIteration(ctx context.Context, cfg *config.Config, timeout time.Duration, p *printer, controller *relay.Controller, prevModes map[string]relay.Mode, lanStore *discovery.Store, dirHolder *atomic.Pointer[directory.Directory]) error {
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
	if dirHolder != nil {
		dirCopy := res.Directory
		dirHolder.Store(&dirCopy)
	}
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
	if lanStore != nil {
		markLANFailures(decision.PeerStates, prevModes, lanStore, time.Now())
	}
	logRelayTransitions(p, res.Directory, decision, prevModes)
	var lanLookup wg.LANEndpointLookup
	if lanStore != nil {
		lanLookup = func(pubkey string) string {
			return lanStore.Lookup(pubkey, time.Now())
		}
	}
	if err := manager.Apply(self, res.Directory, decision.Relayed, lanLookup); err != nil {
		return err
	}
	if lanStore != nil {
		if port, err := manager.ListenPort(); err == nil {
			lanStore.SetSelf(self.PublicKey, port)
		}
		if err := cache.WriteDiscovery(cfg.Sync.Cache, lanStore.Snapshot()); err != nil {
			slog.Debug("write discovery state failed", "error", err)
		}
	}
	relayedNames := relayedPeerNames(res.Directory, decision.Relayed)
	relayVia := ""
	if decision.RelayTarget != nil {
		relayVia = decision.RelayTarget.Name
	}
	slog.Debug("applied directory",
		"serial", res.Serial,
		"peers", len(res.Directory.Nodes)-1,
		"relayed_count", len(decision.Relayed),
		"relayed_peers", relayedNames,
		"relay_target", relayVia,
	)
	if cfg.Observe.IsEnabled() {
		if err := runAdminObservation(ctx, cfg, manager, res.Serial, p); err != nil {
			// Observation defaults on but only applies to admin nodes. When the
			// operator asked for it explicitly, surface the misconfiguration;
			// when it is merely the default on a non-admin node, skip quietly.
			if cfg.Observe.Enabled != nil && *cfg.Observe.Enabled {
				return err
			}
			slog.Debug("skipping endpoint observation (node is not admin)", "error", err)
		}
	}
	return nil
}

// markLANFailures invalidates LAN endpoints for peers that just transitioned
// DIRECT → RELAYED. The kernel was using whatever chooseEndpoint picked
// (operator > LAN > observed), and a stale-handshake transition is the
// signal that endpoint isn't working. Blacklisting clears on the next
// beacon that arrives, by virtue of LearnedAt > FailedAt.
func markLANFailures(states map[string]relay.PeerState, prev map[string]relay.Mode, lanStore *discovery.Store, now time.Time) {
	for key, state := range states {
		old, hadOld := prev[key]
		if !hadOld {
			continue
		}
		if old == relay.ModeDirect && state.Mode == relay.ModeRelayed {
			lanStore.MarkFailed(key, now)
		}
	}
}

func relayedPeerNames(dir directory.Directory, relayed map[string]bool) []string {
	if len(relayed) == 0 {
		return nil
	}
	names := make([]string, 0, len(relayed))
	for _, node := range dir.Nodes {
		if relayed[node.PublicKey] {
			names = append(names, node.Name)
		}
	}
	return names
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
	updated, changed := admin.MergeObservations(source, peers, time.Now(), handshakeFresh)
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
	diff := directory.Compare(source, updated)
	slog.Info("republished after endpoint observation",
		"prev_serial", source.Serial,
		"serial", updated.Serial,
		"changes", diff.Summary(),
	)
	p.headline("republished after endpoint observation (serial: %d): %s", updated.Serial, diff.Summary())
	return nil
}

// startDiscovery launches the LAN discovery goroutines if discovery is
// enabled in the config. Returns nil (with a logged warning) if discovery
// is disabled, the config can't be loaded, or the listeners/senders fail
// to initialize — the daemon continues without LAN discovery in that case.
func startDiscovery(ctx context.Context, configPath string, dirSource discovery.DirectorySource, wakeCh chan<- string, perr *printer) *discovery.Store {
	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Debug("discovery setup skipped (config not loadable)", "error", err)
		return nil
	}
	if !cfg.Discovery.IsEnabled() {
		slog.Info("discovery disabled in config")
		return nil
	}
	dCfg := discovery.Config{
		MulticastIPv4:   cfg.Discovery.MulticastIPv4,
		MulticastIPv6:   cfg.Discovery.MulticastIPv6,
		BeaconInterval:  cfg.Discovery.BeaconInterval.Or(config.DefaultDiscoveryBeaconInterval),
		BeaconTTL:       cfg.Discovery.BeaconTTL.Or(config.DefaultDiscoveryBeaconTTL),
		InterfaceFilter: cfg.Wireguard.Interface,
	}
	store, err := discovery.Start(ctx, dCfg, dirSource, wakeCh)
	if err != nil {
		slog.Warn("discovery start failed", "error", err)
		perr.fail("discovery start failed; %v", err)
		return nil
	}
	slog.Info("discovery started",
		"ipv4", dCfg.MulticastIPv4,
		"ipv6", dCfg.MulticastIPv6,
		"interval", dCfg.BeaconInterval,
		"ttl", dCfg.BeaconTTL,
	)
	return store
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
