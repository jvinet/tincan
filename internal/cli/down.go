package cli

import (
	"context"
	"errors"
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
			p.headline("interface %s is already down", cfg.Wireguard.Interface)
			return nil
		}
		return err
	}
	p.headline("bringing down interface %s", cfg.Wireguard.Interface)
	return nil
}
