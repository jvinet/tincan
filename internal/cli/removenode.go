package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
)

type RemoveNodeCmd struct {
	Name      string `required:"" help:"Node name to remove."`
	NoPublish bool   `name:"no-publish" help:"Save changes to the working directory without publishing to the drop."`
}

func (c *RemoveNodeCmd) Run(ctx context.Context, g *Globals) error {
	cfg, err := loadConfig(g)
	if err != nil {
		return err
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
	node, idx, ok := nodeByName(dir, c.Name)
	if !ok {
		return fmt.Errorf("node %q not found", c.Name)
	}
	dir.Nodes = append(dir.Nodes[:idx], dir.Nodes[idx+1:]...)
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
	slog.Info("removed node", "name", c.Name, "freed_ip", node.TunnelIP, "no_publish", c.NoPublish, "serial", dir.Serial)
	p := newPrinter(os.Stdout)
	p.headline("removed node %q", c.Name)
	p.blank()
	p.pairs(kv("freed IP", node.TunnelIP))
	p.blank()
	if c.NoPublish {
		p.hint("Changes saved locally; run `tincan publish` to revoke and upload to the drop")
	} else {
		p.hint("Removed peers disappear from other nodes after their next sync")
		p.hint("This publish re-encrypts to the remaining members only: %q can no longer decrypt the directory", c.Name)
	}
	return nil
}
