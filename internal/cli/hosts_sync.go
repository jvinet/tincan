package cli

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/hosts"
)

// hostsSyncer reconciles the managed hosts block with the directory after
// every successful apply. It never fails the iteration — a read-only /etc, a
// symlinked hosts file, or malformed markers degrade name resolution, not the
// tunnel — and it dedupes its warning so a permanent condition doesn't spam
// the operator every sync interval.
type hostsSyncer struct {
	lastWarn string
}

// hostsPath returns the hosts file the managed block lives in.
func hostsPath(cfg *config.Config) string {
	if cfg.DNS.HostsPath != "" {
		return cfg.DNS.HostsPath
	}
	return hosts.DefaultPath
}

// sync applies dir's hosts block. It runs even when the directory carries no
// domain: hosts.Block is then empty and Apply strips a stale block exactly
// once after `set-domain --clear`, then no-ops.
func (h *hostsSyncer) sync(cfg *config.Config, dir directory.Directory, p *printer) {
	if !cfg.DNS.ManageHostsEnabled() {
		return
	}
	path := hostsPath(cfg)
	block := hosts.Block(dir)
	changed, err := hosts.Apply(path, block)
	if err != nil {
		slog.Warn("hosts block update failed", "path", path, "error", err)
		// Dedupe on the root cause, not the full message: renameio errors
		// embed a random temp filename, so the same EROFS/EACCES would
		// otherwise read as "new" every sync interval.
		if key := rootCause(err); key != h.lastWarn {
			h.lastWarn = key
			p.warn("could not update %s: %v", path, err)
		}
		return
	}
	h.lastWarn = ""
	if !changed {
		return
	}
	if block == "" {
		slog.Info("hosts block removed", "path", path)
		p.headline("removed VPN DNS entries from %s", path)
		return
	}
	entries := strings.Count(block, "\n")
	slog.Info("hosts block updated", "path", path, "entries", entries, "domain", dir.Domain)
	p.headline("updated VPN DNS entries in %s (%d names under %s)", path, entries, dir.Domain)
}

// rootCause unwraps err to its innermost error string — a stable identity
// for "is this the same failure as last time" comparisons.
func rootCause(err error) string {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err.Error()
		}
		err = next
	}
}

// removeHostsBlock strips the managed block on teardown so VPN names don't
// dangle at unreachable tunnel IPs while the interface is down. Warn-don't-
// fail, like sync.
func removeHostsBlock(cfg *config.Config, p *printer) {
	if !cfg.DNS.ManageHostsEnabled() {
		return
	}
	path := hostsPath(cfg)
	changed, err := hosts.Apply(path, "")
	if err != nil {
		slog.Warn("hosts block removal failed", "path", path, "error", err)
		p.warn("could not remove VPN DNS entries from %s: %v", path, err)
		return
	}
	if changed {
		slog.Info("hosts block removed", "path", path)
		p.headline("removed VPN DNS entries from %s", path)
	}
}
