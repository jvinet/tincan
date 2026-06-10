package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/jvinet/tincan/internal/bootstrap"
	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/keys"
	"golang.org/x/term"
)

type JoinCmd struct {
	Bootstrap      string `type:"path" help:"Path to a bootstrap JSON file produced by the admin."`
	DropType       string `enum:"s3,http,file,dns," default:"" help:"Dead-drop backend type (required without --bootstrap)."`
	Name           string `help:"Node name (required without a node-level --bootstrap)."`
	PrivateKeyFile string `type:"path" help:"Read WireGuard private key from this file."`
	GenerateKey    bool   `help:"Generate a fresh WireGuard keypair locally."`
	StateDir       string `type:"path" help:"Directory for the cache and sibling state files (default /var/lib/tincan)."`
	FullConfig     bool   `help:"Write every applicable section and field at its default, not just the fields likely to be changed."`
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

	keyset, err := c.resolveKeys(bs)
	if err != nil {
		return err
	}

	cfg := config.Config{
		Wireguard: config.WireguardConfig{
			Name:       nodeName,
			PublicKey:  keyset.wgPublic,
			PrivateKey: keyset.wgPrivate,
		},
		Directory: config.DirectoryConfig{
			NetworkIdentity: keyset.ageIdentity,
			PublisherPubKey: publisherPubKey,
		},
		Drop: dropConfig,
	}
	// The admin captured this node's listen port (the port of its published
	// endpoint) in the bootstrap. Bind it so the node is reachable at the
	// endpoint peers were given; without it WireGuard would pick an ephemeral
	// port and inbound handshakes to the published endpoint would fail.
	if bs != nil && bs.Node != nil {
		cfg.Wireguard.ListenPort = bs.Node.ListenPort
	}
	if c.StateDir != "" && c.StateDir != config.DefaultStateDir {
		cfg.Sync.StateDir = c.StateDir
	}
	if c.FullConfig {
		// Discovery applies to every role and defaults on; spell it out so the
		// full config surfaces the knob.
		cfg.Discovery.Enabled = boolPtr(true)
	}
	if err := saveConfig(g.Config, cfg, c.FullConfig); err != nil {
		return err
	}
	// Seed the rollback high-water mark with the serial current at
	// enrollment, so the very first sync already refuses an older directory.
	if bs != nil && bs.Serial > 0 {
		stateDir := cfg.Sync.StateDir
		if stateDir == "" {
			stateDir = config.DefaultStateDir
		}
		if err := cache.WriteSerialFloor(stateDir, bs.Serial); err != nil {
			return err
		}
	}
	slog.Info("initialized client node", "name", nodeName, "config", g.Config, "from_bootstrap", bs != nil)
	p := newPrinter(os.Stdout)
	p.headline("initialized client node %q", nodeName)
	p.blank()
	p.section("Paths")
	p.pairs(kv("config", g.Config))
	p.blank()
	p.section("WireGuard")
	p.pairs(kv("public key", keyset.wgPublic))
	if c.GenerateKey {
		p.blank()
		p.section("age recipient")
		p.pairs(kv("recipient", keyset.ageRecipient))
	}
	p.blank()
	switch {
	case bs != nil && bs.Node != nil:
		p.hint("Next steps: run `tincan up`")
	case bs != nil:
		p.hint("Next steps: run `tincan up` (the directory will identify this node by name and key)")
	case c.GenerateKey:
		p.hint("Send the public key and age recipient to the admin to run `tincan add-node --pub-key <key> --age-recipient <recipient>`")
		p.hint("Then verify [drop.client] and the publisher_pubkey, and run `tincan up`")
	default:
		p.hint("Next steps: fill [directory] (network_identity, publisher_pubkey) and verify [drop.client], then run `tincan up`")
	}
	firewallHint(p, cfg.Wireguard.ListenPort)
	return nil
}

// firewallHint tells the operator which inbound UDP ports a host firewall
// must allow for direct connectivity. The WireGuard port receives peer
// handshakes; the discovery port receives LAN beacons. Blocking either
// degrades the node to relay-only against same-LAN peers — and since the
// node keeps transmitting beacons and syncing the directory, it looks
// healthy from the outside, making the failure otherwise silent.
func firewallHint(p *printer, listenPort int) {
	if listenPort > 0 {
		p.hint("Firewall: allow inbound UDP %d (WireGuard handshakes) and UDP %d (LAN discovery beacons) so peers can connect directly", listenPort, discoveryPort())
		return
	}
	p.hint("Firewall: allow inbound UDP %d (LAN discovery beacons) so same-LAN peers can be found", discoveryPort())
	p.hint("WireGuard will bind a random port; set [wireguard].listen_port and allow it through the firewall so peers can connect directly")
}

// discoveryPort extracts the beacon port from the default multicast group
// address, so the hint stays correct if the default ever changes.
func discoveryPort() int {
	_, portStr, err := net.SplitHostPort(config.DefaultDiscoveryMulticastIPv4)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(portStr)
	return port
}

// keyset is the material join writes into the client config: the WireGuard
// keypair plus the node's own age identity (and, when generated locally, the
// recipient to hand to the admin).
type keyset struct {
	wgPrivate    string
	wgPublic     string
	ageIdentity  string
	ageRecipient string
}

func (c *JoinCmd) resolveKeys(bs *bootstrap.Bootstrap) (keyset, error) {
	// Admin generated the node's keys and delivered them in the bootstrap.
	if bs != nil && bs.Node != nil && bs.Node.PrivateKey != "" {
		if c.GenerateKey || c.PrivateKeyFile != "" {
			return keyset{}, errors.New("bootstrap already contains a WireGuard private key")
		}
		return keyset{wgPrivate: bs.Node.PrivateKey, wgPublic: bs.Node.PublicKey, ageIdentity: bs.Node.AgeIdentity}, nil
	}
	// Operator generates both keypairs locally; the secrets never leave this
	// machine. The public key and age recipient are printed for the admin's
	// `add-node --pub-key … --age-recipient …`.
	if c.GenerateKey {
		wgPriv, wgPub, err := keys.GenerateWGKeypair()
		if err != nil {
			return keyset{}, err
		}
		if err := verifyPubKey(bs, wgPub); err != nil {
			return keyset{}, err
		}
		ageID, ageRcpt, err := keys.GenerateAgeIdentity()
		if err != nil {
			return keyset{}, err
		}
		return keyset{wgPrivate: wgPriv, wgPublic: wgPub, ageIdentity: ageID, ageRecipient: ageRcpt}, nil
	}
	// Manual: read the WG private key; the age identity is filled into
	// [directory].network_identity by hand (the printed next-steps say so).
	priv, err := c.readPrivateKey()
	if err != nil {
		return keyset{}, err
	}
	pub, err := keys.PublicKeyFromWGPrivate(priv)
	if err != nil {
		return keyset{}, err
	}
	if err := verifyPubKey(bs, pub); err != nil {
		return keyset{}, err
	}
	return keyset{wgPrivate: priv, wgPublic: pub}, nil
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
	// Suppress terminal echo so the pasted key doesn't linger on screen or in
	// scrollback. Falls back to a plain line read when stdin isn't a TTY
	// (e.g. piped input in scripts/tests), where echo isn't a concern.
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		line, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		key := trimSecret(string(line))
		if key == "" {
			return "", fmt.Errorf("no private key provided")
		}
		return key, nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("no private key provided")
	}
	return trimSecret(scanner.Text()), nil
}
