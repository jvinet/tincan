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
		cached, _, err := cache.Read(cfg.Sync.StateDir)
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
		slog.Info("synced", "source", syncSource(res), "serial", res.Serial)
		if res.FromCache && res.StaleErr != nil {
			slog.Warn("drop unreachable during up, serving stale cache", "error", res.StaleErr, "serial", res.Serial)
		}
		p.reportSync(res)
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
	if _, err := manager.Apply(self, dir, nil, nil); err != nil {
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
	// endpointPushedAt records, per peer pubkey, when Apply last pushed an
	// endpoint into the kernel from configuration. Endpoint observation
	// consults it so only endpoints validated by a later handshake are ever
	// republished (see admin.MergeObservations).
	endpointPushedAt := map[string]time.Time{}
	for {
		cfg, err := config.Load(configPath)
		if err != nil {
			slog.Error("config load failed", "error", err, "path", configPath)
			perr.fail("failed to load config; %v", err)
		} else {
			timeout := iterationTimeout(cfg.Sync.Interval.Or(config.DefaultInterval))
			if err := runDaemonIteration(ctx, cfg, timeout, pout, controller, prevModes, lanStore, &dirHolder, endpointPushedAt); err != nil {
				slog.Warn("daemon iteration failed", "error", err)
				perr.fail("daemon iteration failed; %v", err)
			}
		}
		interval := config.DefaultInterval
		if cfg != nil {
			interval = cfg.Sync.Interval.Or(config.DefaultInterval)
		}
		proceed, err := waitForReconcile(ctx, sigCh, wakeCh, interval, minWakeInterval, time.Now(), pout)
		if !proceed {
			return err
		}
	}
}

// minWakeInterval is the minimum spacing between wake-triggered reconciles.
// A wake nudges the daemon to reconverge immediately, but each reconcile does
// a drop fetch and a netlink reconfigure; without this floor a beacon storm
// (or a dual-homed peer whose endpoint flaps) could drive back-to-back
// fetches. SIGHUP and the regular interval are never debounced.
const minWakeInterval = 10 * time.Second

// waitForReconcile blocks until the daemon should reconcile again — the sync
// interval elapsed, a SIGHUP arrived, or a wake fired (debounced to at most
// one per minWakeInterval). It returns proceed=false with the error the
// daemon loop should return (nil for a clean shutdown signal).
func waitForReconcile(ctx context.Context, sigCh <-chan os.Signal, wakeCh <-chan string, interval, minWake time.Duration, lastReconcile time.Time, p *printer) (bool, error) {
	intervalDeadline := lastReconcile.Add(interval)
	timer := time.NewTimer(time.Until(intervalDeadline))
	defer timer.Stop()
	var wakePending bool
	for {
		select {
		case <-ctx.Done():
			slog.Info("daemon loop exiting", "reason", "context canceled")
			return false, ctx.Err()
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				slog.Info("received SIGHUP, reloading config and reconciling")
				p.hint("received SIGHUP, reloading config and reconciling")
				return true, nil
			case syscall.SIGTERM, syscall.SIGINT:
				slog.Info("received shutdown signal", "signal", sig.String())
				p.hint("received shutdown signal (%s)", sig.String())
				return false, nil
			}
		case reason := <-wakeCh:
			wakeDeadline := lastReconcile.Add(minWake)
			if !time.Now().Before(wakeDeadline) {
				slog.Info("received wake, reconciling", "reason", reason)
				p.hint("received wake (%s), reconciling", reason)
				return true, nil
			}
			if !wakePending {
				// Coalesce: fire at the debounce deadline, or the regular
				// interval if that comes first. Later wakes fold into this one.
				slog.Debug("wake debounced", "reason", reason, "until", wakeDeadline)
				next := intervalDeadline
				if wakeDeadline.Before(next) {
					next = wakeDeadline
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(time.Until(next))
				wakePending = true
			}
		case <-timer.C:
			return true, nil
		}
	}
}

func runDaemonIteration(ctx context.Context, cfg *config.Config, timeout time.Duration, p *printer, controller *relay.Controller, prevModes map[string]relay.Mode, lanStore *discovery.Store, dirHolder *atomic.Pointer[directory.Directory], endpointPushedAt map[string]time.Time) error {
	res, err := runSyncOnce(ctx, cfg, timeout)
	if err != nil {
		return err
	}
	slog.Info("synced", "source", syncSource(res), "serial", res.Serial)
	if res.FromCache && res.StaleErr != nil {
		slog.Warn("drop unreachable, serving stale cache", "error", res.StaleErr, "serial", res.Serial)
	}
	p.reportSync(res)
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
		lanLookup = func(pubkey string, staleOK bool) string {
			if staleOK {
				return lanStore.LookupLastKnown(pubkey)
			}
			return lanStore.Lookup(pubkey, time.Now())
		}
	}
	pushed, applyErr := manager.Apply(self, res.Directory, decision.Relayed, lanLookup)
	// Record push times before acting on the error: once ConfigureDevice
	// succeeded the endpoints are in the kernel, and observation must not
	// treat them as wire-derived even if a later Apply step failed.
	recordEndpointPushes(endpointPushedAt, pushed, res.Directory, time.Now())
	if applyErr != nil {
		return applyErr
	}
	if lanStore != nil {
		if port, err := manager.ListenPort(); err == nil {
			lanStore.SetSelf(self.PublicKey, port)
		}
		// Reclaim entries for nodes that left the directory and any that have
		// gone unrefreshed for 10× the beacon TTL (spec/lan-discovery.md).
		members := make(map[string]bool, len(res.Directory.Nodes))
		for i := range res.Directory.Nodes {
			members[res.Directory.Nodes[i].PublicKey] = true
		}
		if n := lanStore.GC(time.Now(), 10*lanStore.TTL(), members); n > 0 {
			slog.Debug("discovery store gc", "removed", n)
		}
		if err := cache.WriteDiscovery(cfg.Sync.StateDir, lanStore.Snapshot()); err != nil {
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
		if err := runAdminObservation(ctx, cfg, manager, res.Serial, p, endpointPushedAt); err != nil {
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

// recordEndpointPushes stamps the push time for every peer whose endpoint
// Apply just wrote into the kernel, and prunes entries for peers that have
// left the directory so the map doesn't grow across membership churn.
func recordEndpointPushes(pushedAt map[string]time.Time, pushed []string, dir directory.Directory, now time.Time) {
	if pushedAt == nil {
		return
	}
	for _, key := range pushed {
		pushedAt[key] = now
	}
	if len(pushedAt) == 0 {
		return
	}
	current := make(map[string]bool, len(dir.Nodes))
	for i := range dir.Nodes {
		current[dir.Nodes[i].PublicKey] = true
	}
	for key := range pushedAt {
		if !current[key] {
			delete(pushedAt, key)
		}
	}
}

// markLANFailures invalidates LAN endpoints for peers that just transitioned
// DIRECT → RELAYED. The kernel was using whatever chooseEndpoint picked
// (operator > LAN > observed), and a stale-handshake transition is the
// signal that endpoint isn't working. Blacklisting clears on the next
// beacon that arrives, by virtue of LearnedAt > FailedAt. Peers behind the
// same NAT as self bypass the blacklist (chooseEndpoint looks up with
// staleOK=true): their observed endpoint is a hairpin address, so the
// last-known LAN endpoint stays the probe target regardless.
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

func runAdminObservation(ctx context.Context, cfg *config.Config, manager *wg.Manager, syncedSerial uint64, p *printer, endpointPushedAt map[string]time.Time) error {
	if err := config.RequireAdmin(*cfg); err != nil {
		return fmt.Errorf("[observe].enabled requires admin role: %w", err)
	}
	source, err := cache.ReadSource(cfg.Sync.StateDir)
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
	updated, changed := admin.MergeObservations(source, peers, time.Now(), handshakeFresh, endpointPushedAt)
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
