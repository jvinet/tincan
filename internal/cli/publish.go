package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/drop"
)

type PublishCmd struct {
	Force bool `help:"Publish even when the current remote directory cannot be fetched first."`
}

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
	source, err := cache.ReadSource(cfg.Sync.StateDir)
	if err != nil {
		return fmt.Errorf("read working directory: %w", err)
	}
	p := newPrinter(os.Stdout)
	remote, fetchErr := fetchDirectory(ctx, cfg, d)
	if err := reconcilePublishSerial(&source, remote, fetchErr, c.Force); err != nil {
		slog.Error("publish refused", "error", err)
		return err
	}
	switch {
	case fetchErr == nil:
	case errors.Is(fetchErr, drop.ErrNotFound):
		p.hint("no directory at the drop yet; publishing the first one")
	default: // forced past a fetch failure
		slog.Warn("publishing without the remote serial check", "error", fetchErr)
		p.warn("publishing without the remote serial check (--force); %v", fetchErr)
	}
	if err := bumpDirectory(&source); err != nil {
		return err
	}
	if err := publishDirectory(ctx, cfg, d, source, true); err != nil {
		slog.Error("publish failed", "error", err)
		return err
	}
	slog.Info("published directory", "serial", source.Serial, "nodes", len(source.Nodes))
	p.headline("published directory (serial: %d)", source.Serial)
	return nil
}
