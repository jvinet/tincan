package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/jvinet/tincan/internal/config"
)

type RemoveNodeCmd struct {
	Name string `required:"" help:"Node name to remove."`
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
	if err := bumpDirectory(&dir); err != nil {
		return err
	}
	if err := publishDirectory(ctx, cfg, d, dir, true); err != nil {
		return err
	}
	p := newPrinter(os.Stdout)
	p.headline("removed node %q", c.Name)
	p.blank()
	p.pairs(kv("freed IP", node.TunnelIP))
	p.blank()
	p.hint("Removed peers disappear from other nodes after their next sync")
	return nil
}
