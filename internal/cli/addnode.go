package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/jvinet/tincan/internal/bootstrap"
	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
)

const (
	clientTincan    = "tincan"
	clientWireGuard = "wireguard"
)

type AddNodeCmd struct {
	Name       string `required:"" help:"Node name to add."`
	ClientType string `name:"client-type" enum:"tincan,wireguard" default:"tincan" help:"Kind of client being enrolled: 'tincan' (runs the Tincan agent) or 'wireguard' (plain WireGuard, e.g. a phone)."`
	PubKey     string `help:"Existing WireGuard public key for the node."`
	Endpoint   string `help:"Published endpoint for the node, as host:port."`
	Relay      bool   `help:"Mark this node as a relay: peers route through it when a direct path is unavailable (requires --endpoint)."`
	NoPublish  bool   `name:"no-publish" help:"Save changes to the working directory without publishing to the drop."`

	Bootstrap    string `group:"tincanclient" type:"path" help:"Write a node bootstrap JSON file at this path."`
	AgeRecipient string `group:"tincanclient" name:"age-recipient" help:"Existing age recipient (age1…) for the node; pair with --pub-key when the operator generated the node's keys locally."`

	WGQR     bool   `group:"wgclient" name:"wg-qr" help:"Print the WireGuard config as a QR code on stdout, for the mobile WireGuard app."`
	WGQRPNG  string `group:"wgclient" name:"wg-qr-png" type:"path" help:"Write the WireGuard config QR code to this PNG file."`
	WGConfig string `group:"wgclient" name:"wg-config" type:"path" help:"Write the wg-quick config to this file."`
}

func (c *AddNodeCmd) Run(ctx context.Context, g *Globals) error {
	if err := c.validateFlags(); err != nil {
		return err
	}
	// The endpoint's port is the node's WireGuard listen port: peers reach it
	// there, so the node must bind that port. Parse it before mutating the
	// directory so a malformed --endpoint fails fast, and carry it into the
	// bootstrap so `join` writes it to the client's config.
	listenPort, err := listenPortFromEndpoint(c.Endpoint)
	if err != nil {
		return err
	}
	wgClient := c.ClientType == clientWireGuard

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
	// A tincan node decrypts the directory with its own age key. Generate one
	// alongside a generated WG keypair; for the bring-your-own-keys flow the
	// operator supplies the recipient via --age-recipient (the secret never
	// leaves their machine). Plain-WireGuard nodes don't run tincan, so they
	// get no age key and are simply not directory recipients.
	ageRecipient := c.AgeRecipient
	generatedAgeIdentity := ""
	if !wgClient {
		if ageRecipient == "" {
			id, rcpt, err := keys.GenerateAgeIdentity()
			if err != nil {
				return err
			}
			generatedAgeIdentity = id
			ageRecipient = rcpt
		} else if _, err := keys.ParseAgeRecipient(ageRecipient); err != nil {
			return err
		}
	}
	for _, node := range dir.Nodes {
		if node.PublicKey == publicKey {
			return fmt.Errorf("public key already belongs to node %q", node.Name)
		}
	}
	// A plain WireGuard client peers with a single reachable hub. Resolve it
	// before mutating the directory so we fail without leaving a half-added node.
	var hub directory.Node
	if wgClient {
		h, ok := peerHub(dir, publicKey)
		if !ok {
			return errors.New("--client-type=wireguard needs a hub peer with a public endpoint, but no node has one; add a reachable node first with `tincan add-node --endpoint host:port`")
		}
		hub = h
	}
	tunnelIP, err := directory.NextFreeIP(dir.NetworkCIDR, takenIPs(dir))
	if err != nil {
		return err
	}

	// Render and write the file-based WireGuard artifacts before publishing: a
	// bad path should fail here, not after the node is in the directory (there
	// is no command to regenerate a plain-WireGuard config for an existing node).
	wgConf := ""
	if wgClient {
		wgConf = renderWGQuickConfig(generatedPrivateKey, tunnelIP, dir.NetworkCIDR, hub)
		if c.WGQRPNG != "" {
			png, err := qrPNG(wgConf, 512)
			if err != nil {
				return fmt.Errorf("render QR PNG: %w", err)
			}
			if err := writeSecretFile(c.WGQRPNG, png); err != nil {
				return fmt.Errorf("write QR PNG %s: %w", c.WGQRPNG, err)
			}
		}
		if c.WGConfig != "" {
			if err := writeSecretFile(c.WGConfig, []byte(wgConf)); err != nil {
				return fmt.Errorf("write WireGuard config %s: %w", c.WGConfig, err)
			}
		}
	}

	dir.Nodes = append(dir.Nodes, directory.Node{Name: c.Name, PublicKey: publicKey, TunnelIP: tunnelIP, AgeRecipient: ageRecipient, Endpoint: c.Endpoint, Relay: c.Relay})
	if c.NoPublish {
		if err := cache.WriteSource(cfg.Sync.StateDir, dir); err != nil {
			return err
		}
	} else {
		if err := bumpDirectory(&dir); err != nil {
			return err
		}
		if err := publishDirectory(ctx, cfg, d, dir, true); err != nil {
			return err
		}
	}
	if c.Bootstrap != "" {
		node := bootstrap.Node{
			Name:        c.Name,
			TunnelIP:    tunnelIP,
			ListenPort:  listenPort,
			PublicKey:   publicKey,
			PrivateKey:  generatedPrivateKey,
			AgeIdentity: generatedAgeIdentity,
		}
		if err := bootstrap.Write(c.Bootstrap, bootstrap.WithNode(bootstrap.Network(cfg, dir.Serial), node)); err != nil {
			return err
		}
	}
	slog.Info("added node", "name", c.Name, "tunnel_ip", tunnelIP, "client_type", c.ClientType, "no_publish", c.NoPublish, "serial", dir.Serial)

	// In terminal-QR mode stdout carries the QR payload (so `… --wg-qr >node.conf`
	// captures only the code); the human-readable summary goes to stderr.
	msgOut := os.Stdout
	if c.WGQR {
		msgOut = os.Stderr
	}
	p := newPrinter(msgOut)
	p.headline("added node %q", c.Name)
	p.blank()
	p.section("Assignment")
	items := []pair{
		kv("allocated IP", tunnelIP),
		kv("public key", publicKey),
	}
	if c.Relay {
		items = append(items, kv("role", "relay"))
	}
	// Keep generated secrets out of the scrollback whenever they already ride
	// in an artifact: the wg-quick QR/conf for a WireGuard client, or the
	// bootstrap JSON for a tincan client. Only echo them when there is no other
	// channel (no --bootstrap), so the operator can still transmit them.
	if !wgClient && c.Bootstrap == "" {
		if generatedPrivateKey != "" {
			items = append(items, secret("private key", generatedPrivateKey))
		}
		if generatedAgeIdentity != "" {
			items = append(items, secret("age identity", generatedAgeIdentity))
		}
	}
	p.pairs(items...)
	if wgClient {
		p.blank()
		p.section("WireGuard client")
		artifacts := []pair{
			kv("mode", "hub-and-spoke"),
			kv("hub peer", fmt.Sprintf("%s (%s)", hub.Name, hub.Endpoint)),
			kv("routes", dir.NetworkCIDR),
		}
		if c.WGQRPNG != "" {
			artifacts = append(artifacts, kv("QR PNG", c.WGQRPNG))
		}
		if c.WGConfig != "" {
			artifacts = append(artifacts, kv("config", c.WGConfig))
		}
		p.pairs(artifacts...)
		p.hint("Snapshot config: the device won't track later directory changes (rotated keys, moved endpoints, new nodes). Re-running add-node fails (the node exists); to refresh, run `tincan render-node --name %s` to reissue with the same key, or `remove-node` then `add-node` for a fresh key.", c.Name)
		if c.WGQR {
			p.blank()
			if err := emitQRTerminal(os.Stdout, wgConf, useColor(os.Stdout)); err != nil {
				return err
			}
		}
	}
	if c.Bootstrap != "" {
		p.blank()
		p.section("Bootstrap")
		p.pairs(kv("file", c.Bootstrap))
	}
	if generatedPrivateKey != "" || generatedAgeIdentity != "" {
		p.blank()
		switch {
		case c.Bootstrap != "":
			p.warn("the bootstrap file contains the node's WireGuard private key and age identity; transmit it over a secure channel")
		case wgClient:
			p.warn("the enrollment artifact embeds the node's WireGuard private key; treat it as a secret and remove it once the device is enrolled")
		default:
			p.warn("transmit the private key and age identity securely to the node operator, then clear this terminal")
		}
	}
	if c.NoPublish {
		p.blank()
		p.hint("Changes saved locally; run `tincan publish` to upload to the drop")
	}
	return nil
}

// validateFlags enforces that the enrollment artifacts match the client type:
// --bootstrap is Tincan-only, and the --wg-* artifacts are WireGuard-only (with
// at least one required, since they tell us which artifact to generate).
func (c *AddNodeCmd) validateFlags() error {
	anyWG := c.WGQR || c.WGQRPNG != "" || c.WGConfig != ""
	// A relay carries other peers' traffic, so it must be reachable. Catch the
	// missing endpoint here, before the node is added, regardless of client type.
	if c.Relay && c.Endpoint == "" {
		return errors.New("--relay requires --endpoint host:port: a relay must publish a reachable address")
	}
	switch c.ClientType {
	case clientWireGuard:
		if c.Bootstrap != "" {
			return errors.New("--bootstrap applies to --client-type=tincan; plain WireGuard clients use --wg-qr, --wg-qr-png, or --wg-config")
		}
		if !anyWG {
			return errors.New("--client-type=wireguard needs at least one enrollment artifact: --wg-qr, --wg-qr-png, or --wg-config")
		}
		if c.PubKey != "" {
			return errors.New("--client-type=wireguard delivers a generated private key in its artifacts; omit --pub-key so tincan generates the keypair")
		}
		if c.Relay {
			return errors.New("--relay applies to --client-type=tincan; a plain WireGuard client is a hub-and-spoke spoke, not a relay")
		}
	default: // tincan
		if anyWG {
			return errors.New("--wg-qr, --wg-qr-png, and --wg-config require --client-type=wireguard")
		}
		if c.AgeRecipient != "" && c.PubKey == "" {
			return errors.New("--age-recipient pairs with --pub-key (the operator's locally generated keys); omit both to have tincan generate the keypair")
		}
		if c.PubKey != "" && c.AgeRecipient == "" {
			return errors.New("--pub-key needs --age-recipient too: a tincan node decrypts the directory with its own age key (use `tincan join --generate-key` to produce both)")
		}
	}
	return nil
}
