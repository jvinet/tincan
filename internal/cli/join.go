package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/keys"
)

type JoinCmd struct {
	DropType       string `required:"" enum:"s3,http,file" help:"Dead-drop backend type."`
	Name           string `required:"" help:"Node name."`
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
	var privateKey, publicKey string
	if c.GenerateKey {
		privateKey, publicKey, err = keys.GenerateWGKeypair()
		if err != nil {
			return err
		}
	} else {
		privateKey, err = c.readPrivateKey()
		if err != nil {
			return err
		}
		publicKey, err = keys.PublicKeyFromWGPrivate(privateKey)
		if err != nil {
			return err
		}
	}
	cfg := config.Default()
	if c.Cache != "" {
		cfg.Sync.Cache = c.Cache
	}
	cfg.Wireguard = config.WireguardConfig{
		Name:       c.Name,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Interface:  config.DefaultInterface,
		MTU:        config.DefaultMTU,
	}
	cfg.Drop = config.SkeletonDrop(c.DropType)
	if err := config.Save(g.Config, cfg); err != nil {
		return err
	}
	fmt.Printf("initialized client node %q\n", c.Name)
	fmt.Printf("config: %s\n", g.Config)
	fmt.Printf("WireGuard public key: %s\n", publicKey)
	if c.GenerateKey {
		fmt.Println("send this public key to the admin so they can run `tincan add-node --pubkey ...`")
	}
	fmt.Println("next steps: fill [directory] and [drop], then run `tincan sync`")
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
