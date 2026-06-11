package cli

import (
	"context"
	"log/slog"
	"net"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/dnsserve"
)

// dnsServerManager owns the VPN DNS listener's lifecycle inside the daemon.
//
// Unlike discovery, the listener can't be started once before the loop: its
// bind address (self's tunnel IP) and domain are only known after the first
// successful sync, and both can change while the daemon runs (set-domain,
// renumbering, a relay role moving). So reconcile runs once per iteration —
// after a successful Apply — and converges the running server to the desired
// (addr, domain, upstream) tuple: start when absent, stop when no longer
// wanted, restart on change.
type dnsServerManager struct {
	server *dnsserve.Server
	cancel context.CancelFunc
	// current is the config the running server was started with; a differing
	// desired config triggers a restart.
	current dnsserve.Config
	// lastWarn dedupes start failures by root cause: EADDRINUSE (the host
	// runs dnsmasq/Pi-hole) is retried every iteration but announced once.
	lastWarn string
	// warnedUpstreamFallback gates the one-time warning when no upstream is
	// configured or discoverable and the hardcoded fallback kicks in.
	warnedUpstreamFallback bool
}

// shouldServeDNS is the serving policy. [dns] serve always wins when set;
// the auto default serves only on a plausible hub — self carries the Relay
// flag, or self is the network's relay target (RelayTarget with an empty
// selfPubKey considers every node: exactly the node peerHub hands to
// plain-WireGuard spokes at enrollment, the only clients that query us).
// Binding :53 fleet-wide would fight members' dnsmasq/Pi-hole for nothing.
func shouldServeDNS(cfg *config.Config, dir directory.Directory, self directory.Node) bool {
	if dir.Domain == "" {
		return false
	}
	if cfg.DNS.Serve != nil {
		return *cfg.DNS.Serve
	}
	if self.Relay {
		return true
	}
	target, ok := directory.RelayTarget(dir, "")
	return ok && target.PublicKey == self.PublicKey
}

func (m *dnsServerManager) reconcile(ctx context.Context, cfg *config.Config, dir directory.Directory, self directory.Node, source dnsserve.DirectorySource, p *printer) {
	if !shouldServeDNS(cfg, dir, self) {
		if m.server != nil {
			m.stop()
			slog.Info("vpn dns listener stopped (no longer serving)")
			p.headline("stopped the VPN DNS listener")
		}
		return
	}
	desired := dnsserve.Config{
		Addr:     net.JoinHostPort(self.TunnelIP, "53"),
		Domain:   dir.Domain,
		Upstream: m.upstream(cfg, p),
	}
	if m.server != nil {
		if m.current == desired {
			return
		}
		m.stop()
		slog.Info("vpn dns listener restarting", "addr", desired.Addr, "domain", desired.Domain)
	}
	serverCtx, cancel := context.WithCancel(ctx)
	server, err := dnsserve.Start(serverCtx, desired, source)
	if err != nil {
		cancel()
		slog.Warn("vpn dns listener failed to start", "addr", desired.Addr, "error", err)
		if key := rootCause(err); key != m.lastWarn {
			m.lastWarn = key
			p.warn("VPN DNS listener could not bind %s: %v — plain-WireGuard spokes have no DNS until this is freed (or set [dns] serve = false to stop trying)", desired.Addr, err)
		}
		return
	}
	m.server = server
	m.cancel = cancel
	m.current = desired
	m.lastWarn = ""
	slog.Info("vpn dns listener started", "addr", desired.Addr, "domain", desired.Domain, "upstream", desired.Upstream)
	p.headline("serving VPN DNS for %s on %s (upstream %s)", desired.Domain, desired.Addr, desired.Upstream)
}

// upstream resolves where non-VPN queries get proxied: the configured
// [dns] upstream, else the system's resolv.conf, else a public resolver as
// a last resort — a hub that can't forward breaks ALL DNS on every spoke,
// which is strictly worse than an opinionated default.
func (m *dnsServerManager) upstream(cfg *config.Config, p *printer) string {
	if cfg.DNS.Upstream != "" {
		return cfg.DNS.Upstream
	}
	if upstream, err := dnsserve.DefaultUpstream(); err == nil {
		return upstream
	}
	if !m.warnedUpstreamFallback {
		m.warnedUpstreamFallback = true
		slog.Warn("no usable nameserver in /etc/resolv.conf; forwarding spoke DNS to 1.1.1.1", "fallback", "1.1.1.1:53")
		p.warn("no usable nameserver in /etc/resolv.conf; forwarding spokes' non-VPN DNS to 1.1.1.1:53 (set [dns] upstream to override)")
	}
	return "1.1.1.1:53"
}

func (m *dnsServerManager) stop() {
	if m.server == nil {
		return
	}
	_ = m.server.Close()
	m.cancel()
	m.server = nil
	m.cancel = nil
	m.current = dnsserve.Config{}
}
