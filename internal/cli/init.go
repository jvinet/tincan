package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jvinet/tincan/internal/admin"
	"github.com/jvinet/tincan/internal/bootstrap"
	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
)

type InitCmd struct {
	Name       string `required:"" help:"Node name."`
	DropType   string `required:"" enum:"s3,http,file,dns" help:"Dead-drop backend type."`
	CIDR       string `default:"10.42.0.0/24" help:"Tunnel network CIDR."`
	Endpoint   string `help:"Published endpoint for this node, as host:port."`
	StateDir   string `type:"path" help:"Directory for the cache and sibling state files (default /var/lib/tincan)."`
	FullConfig bool   `help:"Write every applicable section and field at its default, not just the fields likely to be changed."`
	Force      bool   `help:"Overwrite an existing config."`
}

func (c *InitCmd) Run(_ context.Context, g *Globals) error {
	exists, err := configExists(g.Config)
	if err != nil {
		return err
	}
	if exists && !c.Force {
		return fmt.Errorf("config %s already exists; use --force to overwrite", g.Config)
	}
	wgPriv, wgPub, err := keys.GenerateWGKeypair()
	if err != nil {
		return err
	}
	networkIdentity, networkRecipient, err := keys.GenerateAgeIdentity()
	if err != nil {
		return err
	}
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		return err
	}
	tunnelIP, err := directory.NextFreeIP(c.CIDR, nil)
	if err != nil {
		return err
	}
	listenPort, err := listenPortFromEndpoint(c.Endpoint)
	if err != nil {
		return err
	}
	stateDir := config.DefaultStateDir
	if c.StateDir != "" {
		stateDir = c.StateDir
	}
	cfg := config.Config{
		Wireguard: config.WireguardConfig{
			Name:       c.Name,
			PublicKey:  wgPub,
			PrivateKey: wgPriv,
			ListenPort: listenPort,
		},
		Directory: config.DirectoryConfig{
			NetworkIdentity: networkIdentity,
			PublisherPubKey: publisherPub,
			PublisherKey:    publisherPriv,
		},
		Drop: config.SkeletonDrop(c.DropType),
	}
	if stateDir != config.DefaultStateDir {
		cfg.Sync.StateDir = stateDir
	}
	if c.FullConfig {
		// [observe] is admin-only and ApplyDefaults does not fill it, so set it
		// explicitly when writing a complete config. Both enabled flags default
		// on for an admin node; spell them out at their defaults so the full
		// config surfaces every knob.
		cfg.Observe = config.ObserveConfig{
			Enabled:        boolPtr(true),
			HandshakeFresh: config.NewDuration(admin.DefaultHandshakeFresh),
		}
		cfg.Discovery.Enabled = boolPtr(true)
	}
	dir := directory.Directory{
		SchemaVersion: directory.SchemaVersion,
		Serial:        1,
		CreatedAt:     directory.Stamp(),
		NetworkCIDR:   c.CIDR,
		Nodes: []directory.Node{{
			Name:         c.Name,
			PublicKey:    wgPub,
			TunnelIP:     tunnelIP,
			AgeRecipient: networkRecipient,
			Endpoint:     c.Endpoint,
		}},
	}
	if err := cache.WriteSource(stateDir, dir); err != nil {
		return err
	}
	if err := saveConfig(g.Config, cfg, c.FullConfig); err != nil {
		return err
	}
	netbootPath := bootstrap.DefaultPath(stateDir)
	if err := bootstrap.Write(netbootPath, bootstrap.Network(&cfg, dir.Serial)); err != nil {
		return err
	}
	slog.Info("initialized admin node", "name", c.Name, "config", g.Config, "tunnel_ip", tunnelIP, "drop_type", c.DropType, "network_cidr", c.CIDR)
	p := newPrinter(os.Stdout)
	p.headline("initialized admin node %q", c.Name)
	p.blank()
	p.section("Paths")
	p.pairs(
		kv("config", g.Config),
		kv("state directory", stateDir),
		kv("network bootstrap", netbootPath),
	)
	p.blank()
	p.section("Tunnel")
	p.pairs(kv("allocated IP", tunnelIP))
	p.blank()
	p.section("WireGuard keypair")
	p.pairs(
		kv("public key", wgPub),
		secret("private key", wgPriv),
	)
	p.blank()
	p.section("Node identity (age)")
	p.pairs(
		secret("identity", networkIdentity),
		kv("recipient", networkRecipient),
	)
	p.blank()
	p.section("Publisher keypair")
	p.pairs(
		kv("public key", publisherPub),
		secret("private key", publisherPriv),
	)
	p.blank()
	p.hint("Next steps: edit the [drop.admin] and [drop.client] sections, then run `tincan publish`")
	p.hint("This admin observes NAT'd peer endpoints by default; set [observe].enabled = false to turn it off")
	return nil
}
