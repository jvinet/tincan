package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
)

// SetDomainCmd shows, sets, or clears the network's VPN DNS domain. The domain
// lives in the signed directory, so setting it is an admin mutation like
// add-node/remove-node; showing it only needs read access and works anywhere.
type SetDomainCmd struct {
	Domain    string `arg:"" optional:"" help:"VPN DNS domain to set (e.g. \"vpn\" or \"vpn.home\"). Omit to show the current domain."`
	Clear     bool   `help:"Clear the VPN domain, disabling DNS naming network-wide."`
	NoPublish bool   `name:"no-publish" help:"Save changes to the working directory without publishing to the drop."`
}

func (c *SetDomainCmd) Run(ctx context.Context, g *Globals) error {
	if c.Domain != "" && c.Clear {
		return errors.New("--clear cannot be combined with a domain argument")
	}
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	p := newPrinter(os.Stdout)
	if c.Domain == "" && !c.Clear {
		return c.show(ctx, cfg, p)
	}
	if err := config.RequireAdmin(*cfg); err != nil {
		return err
	}
	d, err := loadAdminDrop(cfg)
	if err != nil {
		return err
	}
	dir, err := fetchAdminDirectory(ctx, cfg, d)
	if err != nil {
		return err
	}
	if c.Clear {
		dir.Domain = ""
	} else {
		domain := directory.NormalizeDomain(c.Domain)
		if err := directory.ValidateDomain(domain); err != nil {
			return fmt.Errorf("domain %q: %v", c.Domain, err)
		}
		if err := namesUsableAsLabels(dir); err != nil {
			return err
		}
		dir.Domain = domain
	}
	if c.NoPublish {
		if err := cache.WriteSource(cfg.Sync.StateDir, dir); err != nil {
			return err
		}
	} else {
		if err := bumpDirectory(&dir); err != nil {
			return err
		}
		if err := publishDirectory(ctx, cfg, d, dir, true); err != nil {
			return err
		}
	}
	if c.Clear {
		slog.Info("cleared VPN domain", "no_publish", c.NoPublish, "serial", dir.Serial)
		p.headline("cleared the VPN domain")
		p.blank()
		p.hint("Members remove their managed hosts entries on their next sync; hubs stop serving DNS")
		warnStrandedSpokes(p, dir)
	} else {
		slog.Info("set VPN domain", "domain", dir.Domain, "no_publish", c.NoPublish, "serial", dir.Serial)
		p.headline("set VPN domain to %q", dir.Domain)
		p.blank()
		p.pairs(kv("example name", exampleFQDN(dir)))
		p.blank()
		p.hint("Members pick up the domain (and their /etc/hosts entries) within one sync interval")
		p.hint("Existing plain-WireGuard configs are snapshots: re-run `tincan render-node` to reissue them with a DNS server line")
	}
	if c.NoPublish {
		p.hint("Changes saved locally; run `tincan publish` to upload to the drop")
	}
	return nil
}

func (c *SetDomainCmd) show(ctx context.Context, cfg *config.Config, p *printer) error {
	d, err := loadReadDrop(cfg)
	if err != nil {
		return err
	}
	dir, err := fetchDirectory(ctx, cfg, d)
	if err != nil {
		return err
	}
	if dir.Domain == "" {
		p.pairs(kv("domain", "(not set)"))
		p.blank()
		p.hint("Set one with `tincan set-domain <domain>` on the admin node")
		return nil
	}
	p.pairs(
		kv("domain", dir.Domain),
		kv("example name", exampleFQDN(dir)),
	)
	return nil
}

// namesUsableAsLabels checks every node name against the DNS label rules a
// domain imposes, reporting all offenders at once so the operator gets a
// single actionable list instead of one rename per attempt.
func namesUsableAsLabels(dir directory.Directory) error {
	var bad []string
	seenLower := make(map[string]string, len(dir.Nodes))
	for _, node := range dir.Nodes {
		if err := directory.ValidateLabel(node.Name); err != nil {
			bad = append(bad, fmt.Sprintf("%q (%v)", node.Name, err))
			continue
		}
		lower := strings.ToLower(node.Name)
		if prev, ok := seenLower[lower]; ok {
			bad = append(bad, fmt.Sprintf("%q (collides with %q: DNS names are case-insensitive)", node.Name, prev))
			continue
		}
		seenLower[lower] = node.Name
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("node names are not usable as DNS labels: %s; rename them (remove-node, then add-node) before setting a domain", strings.Join(bad, ", "))
}

// warnStrandedSpokes calls out plain-WireGuard members after a domain is
// cleared: their snapshot configs still name the hub as their DNS server, and
// once the hub stops serving, those devices lose all DNS while the tunnel is
// up — a much worse failure than losing VPN names.
func warnStrandedSpokes(p *printer, dir directory.Directory) {
	var spokes []string
	for _, node := range dir.Nodes {
		if node.IsPlainWireGuard() {
			spokes = append(spokes, node.Name)
		}
	}
	if len(spokes) == 0 {
		return
	}
	p.blank()
	p.warn("plain-WireGuard configs rendered while the domain was set still point their DNS at the hub, which now stops answering — those devices lose ALL DNS while their tunnel is up. Re-render and re-enroll them: %s", strings.Join(spokes, ", "))
}

func exampleFQDN(dir directory.Directory) string {
	name := "node"
	if len(dir.Nodes) > 0 {
		name = strings.ToLower(dir.Nodes[0].Name)
	}
	return name + "." + dir.Domain
}
