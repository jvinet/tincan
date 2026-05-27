package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
)

type PublishCmd struct{}

func (c *PublishCmd) Run(ctx context.Context, g *Globals) error {
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
	source, err := cache.ReadSource(cfg.Sync.Cache)
	if err != nil {
		return fmt.Errorf("read working directory: %w", err)
	}
	p := newPrinter(os.Stdout)
	remote, err := fetchDirectory(ctx, cfg, d)
	if err == nil && remote.Serial >= source.Serial {
		source.Serial = remote.Serial
	} else if err != nil {
		p.fail("failed to fetch remote directory before publish; %v", err)
	}
	if err := bumpDirectory(&source); err != nil {
		return err
	}
	if err := publishDirectory(ctx, cfg, d, source, true); err != nil {
		return err
	}
	p.headline("published directory (serial: %d)", source.Serial)
	return nil
}
