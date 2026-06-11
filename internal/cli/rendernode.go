package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jvinet/tincan/internal/keys"
)

// RenderNodeCmd regenerates the plain-WireGuard (hub-and-spoke) config for a
// node already in the directory. add-node emits this artifact once at
// enrollment and notes there is no way to recreate it later; render-node is
// that way — for a lost phone config, a re-flashed device, or inspecting what
// wg-quick config a given node resolves to under the current directory.
//
// The admin never stores node private keys, so the rendered config carries a
// PrivateKey placeholder unless the operator supplies --private-key (which is
// validated against the node's published public key). A QR code must be
// directly scannable, so the QR sinks require --private-key.
type RenderNodeCmd struct {
	Name       string `required:"" help:"Name of the directory node to render a config for."`
	PrivateKey string `name:"private-key" help:"The node's WireGuard private key, embedded in the rendered config (omit to leave a fill-in placeholder)."`

	WGQR     bool   `name:"wg-qr" help:"Print the config as a QR code on stdout, for the mobile WireGuard app (requires --private-key)."`
	WGQRPNG  string `name:"wg-qr-png" type:"path" help:"Write the config QR code to this PNG file (requires --private-key)."`
	WGConfig string `name:"wg-config" type:"path" help:"Write the wg-quick config to this file."`
}

func (c *RenderNodeCmd) Run(ctx context.Context, g *Globals) error {
	if err := c.validateFlags(); err != nil {
		return err
	}
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	d, err := loadReadDrop(cfg)
	if err != nil {
		return err
	}
	dir, err := fetchDirectory(ctx, cfg, d)
	if err != nil {
		return err
	}
	node, _, ok := nodeByName(dir, c.Name)
	if !ok {
		return fmt.Errorf("node %q not found in the directory", c.Name)
	}
	// A supplied key must belong to this node, or the rendered config would be
	// silently unusable (its public key wouldn't match what peers expect).
	if c.PrivateKey != "" {
		pub, err := keys.PublicKeyFromWGPrivate(c.PrivateKey)
		if err != nil {
			return err
		}
		if pub != node.PublicKey {
			return fmt.Errorf("--private-key does not match node %q (its public key is %s)", c.Name, node.PublicKey)
		}
	}
	hub, ok := peerHub(dir, node.PublicKey)
	if !ok {
		return fmt.Errorf("node %q has no hub peer with a public endpoint to route through; mark a reachable node with `tincan add-node --relay --endpoint host:port`", c.Name)
	}
	if node.PublicKey == hub.PublicKey {
		return fmt.Errorf("node %q is itself the hub/relay; hub-and-spoke configs are for spoke nodes", c.Name)
	}
	wgConf := renderWGQuickConfig(c.PrivateKey, node.TunnelIP, dir.NetworkCIDR, dir.Domain, hub)

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

	// With no artifact flag, the wg-quick text is the command's only output and
	// goes to stdout verbatim, so `tincan render-node … >node.conf` captures
	// exactly the config. The human-readable summary then goes to stderr.
	bareStdout := !c.WGQR && c.WGQRPNG == "" && c.WGConfig == ""
	msgOut := io.Writer(os.Stdout)
	if c.WGQR || bareStdout {
		msgOut = os.Stderr
	}
	if bareStdout {
		fmt.Fprint(os.Stdout, wgConf)
	}

	p := newPrinter(msgOut)
	p.headline("rendered config for node %q", c.Name)
	p.blank()
	p.section("WireGuard client")
	artifacts := []pair{
		kv("mode", "hub-and-spoke"),
		kv("tunnel IP", node.TunnelIP),
		kv("hub peer", fmt.Sprintf("%s (%s)", hub.Name, hub.Endpoint)),
		kv("routes", dir.NetworkCIDR),
	}
	if dir.Domain != "" {
		artifacts = append(artifacts, kv("DNS", fmt.Sprintf("%s (search domain %s)", hub.TunnelIP, dir.Domain)))
	}
	if c.WGQRPNG != "" {
		artifacts = append(artifacts, kv("QR PNG", c.WGQRPNG))
	}
	if c.WGConfig != "" {
		artifacts = append(artifacts, kv("config", c.WGConfig))
	}
	p.pairs(artifacts...)
	p.hint("Snapshot config: the device won't track later directory changes (rotated keys, moved endpoints, new nodes). Re-run `tincan render-node --name %s` after the directory changes to reissue with the same key; use `remove-node` then `add-node` if the node needs a new key.", c.Name)
	if c.PrivateKey == "" {
		p.hint("No --private-key given: fill in the PrivateKey placeholder with the node's own key before use.")
	} else {
		p.blank()
		p.warn("the rendered config embeds the node's WireGuard private key; treat it as a secret and clear it once the device is enrolled")
	}
	if c.WGQR {
		p.blank()
		if err := emitQRTerminal(os.Stdout, wgConf, useColor(os.Stdout)); err != nil {
			return err
		}
	}
	return nil
}

// validateFlags rejects QR output without a private key: a QR code is meant to
// be scanned straight into the WireGuard app, so a placeholder-key template
// would produce an unusable code.
func (c *RenderNodeCmd) validateFlags() error {
	if (c.WGQR || c.WGQRPNG != "") && c.PrivateKey == "" {
		return errors.New("--wg-qr/--wg-qr-png require --private-key: a QR code must be directly scannable, so it can't contain a placeholder key")
	}
	return nil
}
