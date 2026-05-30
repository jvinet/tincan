package cli

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/jvinet/tincan/internal/wg"
	"github.com/vishvananda/netlink"
)

type DownCmd struct{}

func (c *DownCmd) Run(_ context.Context, g *Globals) error {
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	manager, err := wg.NewManager(cfg.Wireguard)
	if err != nil {
		return err
	}
	p := newPrinter(os.Stdout)
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
