package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jvinet/tincan/internal/bootstrap"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/keys"
)

type JoinCmd struct {
	Bootstrap      string `type:"path" help:"Path to a bootstrap JSON file produced by the admin."`
	DropType       string `enum:"s3,http,file," default:"" help:"Dead-drop backend type (required without --bootstrap)."`
	Name           string `help:"Node name (required without a node-level --bootstrap)."`
	PrivateKeyFile string `type:"path" help:"Read WireGuard private key from this file."`
	GenerateKey    bool   `help:"Generate a fresh WireGuard keypair locally."`
	Cache          string `type:"path" help:"Cache path to write in the generated config."`
	Force          bool   `help:"Overwrite an existing config."`
}

func (c *JoinCmd) Run(_ context.Context, g *Globals) error {
	exists, err := configExists(g.Config)
	if err != nil {
		return err
	}
	if exists && !c.Force {
		return fmt.Errorf("config %s already exists; use --force to overwrite", g.Config)
	}

	var (
		bs              *bootstrap.Bootstrap
		dropConfig      config.DropConfig
		networkIdentity string
		publisherPubKey string
		nodeName        = c.Name
	)
	if c.Bootstrap != "" {
		loaded, err := bootstrap.Read(c.Bootstrap)
		if err != nil {
			return err
		}
		bs = &loaded
		dropConfig = config.DropConfig{Client: bs.Drop}
		networkIdentity = bs.Directory.NetworkIdentity
		publisherPubKey = bs.Directory.PublisherPubKey
		if bs.Node != nil && nodeName == "" {
			nodeName = bs.Node.Name
		}
	} else {
		if c.DropType == "" {
			return errors.New("--drop-type is required when --bootstrap is omitted")
		}
		dropConfig = config.SkeletonClientDrop(c.DropType)
	}
	if nodeName == "" {
		return errors.New("--name is required when the bootstrap does not include node info")
	}

	privateKey, publicKey, err := c.resolveKeys(bs)
	if err != nil {
		return err
	}

	cfg := config.Default()
	if c.Cache != "" {
		cfg.Sync.Cache = c.Cache
	}
	cfg.Wireguard = config.WireguardConfig{
		Name:       nodeName,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Interface:  config.DefaultInterface,
		MTU:        config.DefaultMTU,
	}
	cfg.Directory = config.DirectoryConfig{
		NetworkIdentity: networkIdentity,
		PublisherPubKey: publisherPubKey,
	}
	cfg.Drop = dropConfig
	if err := config.Save(g.Config, cfg); err != nil {
		return err
	}
	p := newPrinter(os.Stdout)
	p.headline("initialized client node %q", nodeName)
	p.blank()
	p.section("Paths")
	p.pairs(kv("config", g.Config))
	p.blank()
	p.section("WireGuard")
	p.pairs(kv("public key", publicKey))
	p.blank()
	switch {
	case bs != nil && bs.Node != nil:
		p.hint("Next steps: run `tincan up`")
	case bs != nil:
		p.hint("Next steps: run `tincan up` (the directory will identify this node by name and key)")
	case c.GenerateKey:
		p.hint("Send this public key to the admin so they can run `tincan add-node --pubkey ...`")
		p.hint("Then fill [directory] in the config and run `tincan up`")
	default:
		p.hint("Next steps: fill [directory] and verify [drop.client], then run `tincan up`")
	}
	return nil
}

func (c *JoinCmd) resolveKeys(bs *bootstrap.Bootstrap) (string, string, error) {
	if bs != nil && bs.Node != nil && bs.Node.PrivateKey != "" {
		if c.GenerateKey || c.PrivateKeyFile != "" {
			return "", "", errors.New("bootstrap already contains a WireGuard private key")
		}
		return bs.Node.PrivateKey, bs.Node.PublicKey, nil
	}
	if c.GenerateKey {
		priv, pub, err := keys.GenerateWGKeypair()
		if err != nil {
			return "", "", err
		}
		if err := verifyPubKey(bs, pub); err != nil {
			return "", "", err
		}
		return priv, pub, nil
	}
	priv, err := c.readPrivateKey()
	if err != nil {
		return "", "", err
	}
	pub, err := keys.PublicKeyFromWGPrivate(priv)
	if err != nil {
		return "", "", err
	}
	if err := verifyPubKey(bs, pub); err != nil {
		return "", "", err
	}
	return priv, pub, nil
}

func verifyPubKey(bs *bootstrap.Bootstrap, pub string) error {
	if bs == nil || bs.Node == nil || bs.Node.PublicKey == "" {
		return nil
	}
	if bs.Node.PublicKey != pub {
		return errors.New("bootstrap public key does not match the provided private key")
	}
	return nil
}

func (c *JoinCmd) readPrivateKey() (string, error) {
	if c.PrivateKeyFile != "" {
		data, err := os.ReadFile(c.PrivateKeyFile)
		if err != nil {
			return "", err
		}
		return trimSecret(string(data)), nil
	}
	fmt.Fprint(os.Stderr, "WireGuard private key: ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("no private key provided")
	}
	return trimSecret(scanner.Text()), nil
}
