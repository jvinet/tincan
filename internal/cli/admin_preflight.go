//go:build linux

package cli

import (
	"log/slog"
	"os"
	"strings"

	"github.com/jvinet/tincan/internal/config"
)

// startAdminPreflight runs one-time admin-only sanity checks at daemon start.
// Today this is just net.ipv4.ip_forward — the relay role can't forward
// peer-to-peer traffic without it. We warn rather than fail; some operators
// might set up forwarding via a different mechanism (iptables marks,
// systemd-sysctl), and we don't want to block startup.
func startAdminPreflight(configPath string, pout *printer) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return
	}
	if err := config.RequireAdmin(*cfg); err != nil {
		return // not an admin — no preflight needed
	}
	if !ipForwardEnabled() {
		slog.Warn("admin preflight: net.ipv4.ip_forward disabled")
		pout.warn("net.ipv4.ip_forward is not enabled; peers that fall back to admin-relay will not reach each other. " +
			"Enable with: sysctl -w net.ipv4.ip_forward=1 (persist via /etc/sysctl.d/)")
	}
}

func ipForwardEnabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}
