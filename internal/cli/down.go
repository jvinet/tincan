package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jvinet/tincan/internal/daemon"
	"github.com/jvinet/tincan/internal/wg"
	"github.com/vishvananda/netlink"
)

// daemonStopWait bounds how long `down --stop` waits for the daemon to exit
// after SIGTERM before giving up. The daemon idles on a 5-minute timer and
// reacts to the signal almost immediately; the wait only matters in the narrow
// window where it is mid-sync and processes signals only once that returns.
const daemonStopWait = 10 * time.Second

type DownCmd struct {
	Stop bool `help:"Also stop the running tincan daemon, if one exists."`
}

func (c *DownCmd) Run(_ context.Context, g *Globals) error {
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	p := newPrinter(os.Stdout)
	if c.Stop {
		// Stop the daemon before teardown so its next reconcile — or an
		// in-flight one — can't bring the interface back up after we drop it.
		pid, err := daemon.Stop(cfg.Sync.PIDFile, daemonStopWait)
		switch {
		case errors.Is(err, daemon.ErrNotRunning):
			slog.Info("no daemon running to stop", "pidfile", cfg.Sync.PIDFile)
			p.hint("no tincan daemon running")
		case err != nil:
			// The signal was delivered but the daemon hasn't exited yet
			// (likely finishing a sync). Don't tear down: a live daemon would
			// re-apply and re-raise the interface. Surface it so the user can
			// retry once it's gone.
			slog.Error("daemon stop incomplete", "pid", pid, "error", err)
			return fmt.Errorf("%w; re-run 'tincan down --stop' once it has exited", err)
		default:
			slog.Info("daemon stopped", "pid", pid)
			p.headline("stopped tincan daemon (pid: %d)", pid)
		}
	}
	manager, err := wg.NewManager(cfg.Wireguard)
	if err != nil {
		return err
	}
	if err := manager.Teardown(); err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			slog.Info("interface already down", "interface", cfg.Wireguard.Interface)
			p.headline("interface %s is already down", cfg.Wireguard.Interface)
			return nil
		}
		slog.Error("teardown failed", "interface", cfg.Wireguard.Interface, "error", err)
		return err
	}
	slog.Info("brought down interface", "interface", cfg.Wireguard.Interface)
	p.headline("bringing down interface %s", cfg.Wireguard.Interface)
	return nil
}
