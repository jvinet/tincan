package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jvinet/tincan/internal/admin"
	"github.com/jvinet/tincan/internal/bootstrap"
	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
)

type InitCmd struct {
	Name     string `required:"" help:"Node name."`
	DropType string `required:"" enum:"s3,http,file" help:"Dead-drop backend type."`
	CIDR     string `default:"10.42.0.0/24" help:"Tunnel network CIDR."`
	Endpoint string `help:"Published endpoint for this node, as host:port."`
	Cache    string `type:"path" help:"Cache path to write in the generated config."`
	Force    bool   `help:"Overwrite an existing config."`
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
	cfg := config.Default()
	if c.Cache != "" {
		cfg.Sync.Cache = c.Cache
	}
	cfg.Wireguard = config.WireguardConfig{
		Name:       c.Name,
		PublicKey:  wgPub,
		PrivateKey: wgPriv,
		Interface:  config.DefaultInterface,
		ListenPort: listenPort,
		MTU:        config.DefaultMTU,
	}
	cfg.Directory = config.DirectoryConfig{
		NetworkIdentity: networkIdentity,
		PublisherPubKey: publisherPub,
		PublisherKey:    publisherPriv,
	}
	cfg.Drop = config.SkeletonDrop(c.DropType)
	cfg.Observe = config.ObserveConfig{
		HandshakeFresh: config.NewDuration(admin.DefaultHandshakeFresh),
	}
	dir := directory.Directory{
		SchemaVersion: directory.SchemaVersion,
		Serial:        1,
		CreatedAt:     time.Now().UTC(),
		NetworkCIDR:   c.CIDR,
		Nodes: []directory.Node{{
			Name:      c.Name,
			PublicKey: wgPub,
			TunnelIP:  tunnelIP,
			Endpoint:  c.Endpoint,
		}},
	}
	if err := cache.WriteSource(cfg.Sync.Cache, dir); err != nil {
		return err
	}
	if err := config.Save(g.Config, cfg); err != nil {
		return err
	}
	netbootPath := bootstrap.DefaultPath(cfg.Sync.Cache)
	if err := bootstrap.Write(netbootPath, bootstrap.Network(&cfg)); err != nil {
		return err
	}
	slog.Info("initialized admin node", "name", c.Name, "config", g.Config, "tunnel_ip", tunnelIP, "drop_type", c.DropType, "network_cidr", c.CIDR)
	p := newPrinter(os.Stdout)
	p.headline("initialized admin node %q", c.Name)
	p.blank()
	p.section("Paths")
	p.pairs(
		kv("config", g.Config),
		kv("working directory", config.SourcePath(cfg.Sync.Cache)),
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
	p.section("Network identity (age)")
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
	p.hint("To let NAT'd peers discover each other's endpoints, set [observe].enabled = true on this admin node")
	return nil
}
