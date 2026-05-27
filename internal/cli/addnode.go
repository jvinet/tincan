package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/jvinet/tincan/internal/bootstrap"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
)

type AddNodeCmd struct {
	Name      string `required:"" help:"Node name to add."`
	PubKey    string `help:"Existing WireGuard public key for the node."`
	Endpoint  string `help:"Published endpoint for the node, as host:port."`
	Bootstrap string `type:"path" help:"Write a node bootstrap JSON file at this path."`
}

func (c *AddNodeCmd) Run(ctx context.Context, g *Globals) error {
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
	if _, _, ok := nodeByName(dir, c.Name); ok {
		return fmt.Errorf("node %q already exists", c.Name)
	}
	publicKey := c.PubKey
	generatedPrivateKey := ""
	if publicKey == "" {
		priv, pub, err := keys.GenerateWGKeypair()
		if err != nil {
			return err
		}
		generatedPrivateKey = priv
		publicKey = pub
	} else if _, err := keys.ParseWGPublic(publicKey); err != nil {
		return err
	}
	for _, node := range dir.Nodes {
		if node.PublicKey == publicKey {
			return fmt.Errorf("public key already belongs to node %q", node.Name)
		}
	}
	tunnelIP, err := directory.NextFreeIP(dir.NetworkCIDR, takenIPs(dir))
	if err != nil {
		return err
	}
	dir.Nodes = append(dir.Nodes, directory.Node{Name: c.Name, PublicKey: publicKey, TunnelIP: tunnelIP, Endpoint: c.Endpoint})
	if err := bumpDirectory(&dir); err != nil {
		return err
	}
	if err := publishDirectory(ctx, cfg, d, dir, true); err != nil {
		return err
	}
	if c.Bootstrap != "" {
		node := bootstrap.Node{
			Name:       c.Name,
			TunnelIP:   tunnelIP,
			PublicKey:  publicKey,
			PrivateKey: generatedPrivateKey,
		}
		if err := bootstrap.Write(c.Bootstrap, bootstrap.WithNode(bootstrap.Network(cfg), node)); err != nil {
			return err
		}
	}
	p := newPrinter(os.Stdout)
	p.headline("added node %q", c.Name)
	p.blank()
	p.section("Assignment")
	items := []pair{
		kv("allocated IP", tunnelIP),
		kv("public key", publicKey),
	}
	if generatedPrivateKey != "" {
		items = append(items, secret("private key", generatedPrivateKey))
	}
	p.pairs(items...)
	if c.Bootstrap != "" {
		p.blank()
		p.section("Bootstrap")
		p.pairs(kv("file", c.Bootstrap))
	}
	if generatedPrivateKey != "" {
		p.blank()
		if c.Bootstrap != "" {
			p.warn("the bootstrap file contains a WireGuard private key; transmit it over a secure channel")
		} else {
			p.warn("transmit this private key securely to the node operator, then clear this terminal")
		}
	}
	return nil
}
