package cli

import (
	"context"
	"fmt"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
)

type AddNodeCmd struct {
	Name     string `required:"" help:"Node name to add."`
	PubKey   string `help:"Existing WireGuard public key for the node."`
	Endpoint string `help:"Published endpoint for the node, as host:port."`
}

func (c *AddNodeCmd) Run(ctx context.Context, g *Globals) error {
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	if err := config.RequireAdmin(*cfg); err != nil {
		return err
	}
	d, err := loadDrop(cfg)
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
	fmt.Printf("added node %q\n", c.Name)
	fmt.Printf("allocated IP: %s\n", tunnelIP)
	fmt.Printf("WireGuard public key: %s\n", publicKey)
	if generatedPrivateKey != "" {
		fmt.Printf("WireGuard private key: %s\n", generatedPrivateKey)
		fmt.Println("transmit this private key securely to the node operator, then clear this terminal")
	}
	return nil
}
