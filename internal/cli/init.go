package cli

import (
	"context"
	"fmt"
	"time"

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
	fmt.Printf("initialized admin node %q\n", c.Name)
	fmt.Printf("config: %s\n", g.Config)
	fmt.Printf("working directory: %s\n", config.SourcePath(cfg.Sync.Cache))
	fmt.Printf("allocated IP: %s\n", tunnelIP)
	fmt.Printf("WireGuard public key: %s\n", wgPub)
	fmt.Printf("WireGuard private key: %s\n", wgPriv)
	fmt.Printf("age identity: %s\n", networkIdentity)
	fmt.Printf("age recipient: %s\n", networkRecipient)
	fmt.Printf("publisher public key: %s\n", publisherPub)
	fmt.Printf("publisher private key: %s\n", publisherPriv)
	fmt.Println("next steps: edit the [drop] section, then run `tincan publish`")
	return nil
}
