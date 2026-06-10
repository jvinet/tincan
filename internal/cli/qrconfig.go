package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/renameio/v2"
	"github.com/jvinet/tincan/internal/directory"
	qrcode "github.com/skip2/go-qrcode"
)

// peerHub returns the directory node that a plain WireGuard (non-Tincan) client
// should peer with in hub-and-spoke mode. It is the network's relay target
// (see directory.RelayTarget): a node explicitly marked Relay, else the first
// node other than the one being enrolled that publishes a reachable endpoint —
// the same node the daemon and `status` route relayed traffic through. ok is
// false when no such node exists.
func peerHub(dir directory.Directory, selfPubKey string) (directory.Node, bool) {
	return directory.RelayTarget(dir, selfPubKey)
}

// renderWGQuickConfig builds a standard wg-quick INI config for a plain
// WireGuard client in hub-and-spoke mode: the whole network CIDR is tunnelled
// through a single hub peer. The mobile WireGuard apps consume exactly this
// text, whether read from a file or decoded from a scanned QR code.
//
// When privateKey is empty the PrivateKey line is emitted as a placeholder
// comment — `render-node` does this when the operator hasn't supplied the
// node's key (which the admin never stores), producing a template the node
// owner completes locally. add-node always passes the freshly generated key,
// so it never hits the placeholder path.
//
// The result is a point-in-time snapshot. Such a client does not run Tincan, so
// it will not track later directory changes (rotated keys, new or moved
// endpoints, membership) — re-enroll it to refresh.
func renderWGQuickConfig(privateKey, tunnelIP, networkCIDR string, hub directory.Node) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if privateKey == "" {
		b.WriteString("# PrivateKey = <paste this node's WireGuard private key>\n")
	} else {
		fmt.Fprintf(&b, "PrivateKey = %s\n", privateKey)
	}
	fmt.Fprintf(&b, "Address = %s/32\n", tunnelIP)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", hub.PublicKey)
	if hub.PSK != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", hub.PSK)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", hub.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", networkCIDR)
	// The client is the NAT-traversing spoke, so it keeps the tunnel alive.
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

// qrPNG renders content as a PNG QR code whose image is size pixels square.
func qrPNG(content string, size int) ([]byte, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	return q.PNG(size)
}

// writeSecretFile atomically writes data to path with 0600 permissions,
// creating the parent directory if needed. Used for enrollment artifacts that
// embed a WireGuard private key, so they are never world-readable.
func writeSecretFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return renameio.WriteFile(path, data, 0o600)
}

// 256-color SGR indices for crisp black-on-white QR cells, independent of the
// terminal's theme.
const (
	qrBlack = 16
	qrWhite = 231
)

// emitQRTerminal writes a scannable QR encoding of content to w using Unicode
// half-block cells, packing two vertical modules per text row so the code stays
// roughly square. When color is true (an interactive terminal) each half is
// painted black or white via ANSI, so the code scans regardless of the
// terminal's color scheme. When color is false (e.g. redirected to a file) it
// emits plain block glyphs that remain re-renderable as text but inherit the
// viewer's colors — fragile to transmit; prefer --qr-png for that.
func emitQRTerminal(w io.Writer, content string, color bool) error {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return err
	}
	// bitmap[y][x] is true for dark modules and already includes the quiet-zone
	// border decoders need.
	bitmap := q.Bitmap()
	var b strings.Builder
	for y := 0; y < len(bitmap); y += 2 {
		for x := 0; x < len(bitmap[y]); x++ {
			top := bitmap[y][x]
			bottom := y+1 < len(bitmap) && bitmap[y+1][x]
			if color {
				// '▀' paints its upper half with the foreground color and its
				// lower half with the background color.
				fg, bg := qrWhite, qrWhite
				if top {
					fg = qrBlack
				}
				if bottom {
					bg = qrBlack
				}
				fmt.Fprintf(&b, "\x1b[38;5;%d;48;5;%dm▀", fg, bg)
			} else {
				switch {
				case top && bottom:
					b.WriteRune('█') // full block
				case top:
					b.WriteRune('▀') // upper half
				case bottom:
					b.WriteRune('▄') // lower half
				default:
					b.WriteRune(' ')
				}
			}
		}
		if color {
			b.WriteString("\x1b[0m")
		}
		b.WriteByte('\n')
	}
	_, err = io.WriteString(w, b.String())
	return err
}
