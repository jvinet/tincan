package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jvinet/tincan/internal/directory"
	qrcode "github.com/skip2/go-qrcode"
)

func TestAddNodeValidateFlags(t *testing.T) {
	tests := []struct {
		name string
		cmd  AddNodeCmd
		ok   bool
	}{
		{"tincan default", AddNodeCmd{ClientType: clientTincan}, true},
		{"tincan with bootstrap", AddNodeCmd{ClientType: clientTincan, Bootstrap: "b.json"}, true},
		{"tincan rejects wg-qr", AddNodeCmd{ClientType: clientTincan, WGQR: true}, false},
		{"tincan rejects wg-config", AddNodeCmd{ClientType: clientTincan, WGConfig: "p.conf"}, false},
		{"wireguard with qr", AddNodeCmd{ClientType: clientWireGuard, WGQR: true}, true},
		{"wireguard with multiple artifacts", AddNodeCmd{ClientType: clientWireGuard, WGQRPNG: "p.png", WGConfig: "p.conf"}, true},
		{"wireguard needs an artifact", AddNodeCmd{ClientType: clientWireGuard}, false},
		{"wireguard rejects bootstrap", AddNodeCmd{ClientType: clientWireGuard, WGQR: true, Bootstrap: "b.json"}, false},
		{"wireguard rejects pubkey", AddNodeCmd{ClientType: clientWireGuard, WGQR: true, PubKey: "k"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.validateFlags()
			if tt.ok && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestQRPNG(t *testing.T) {
	png, err := qrPNG("hello", 256)
	if err != nil {
		t.Fatalf("qrPNG: %v", err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("output is not a PNG (first bytes %x)", png[:min(8, len(png))])
	}
}

func TestWriteSecretFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "node.conf") // sub/ does not exist yet
	want := []byte("PrivateKey = ...\n")
	if err := writeSecretFile(path, want); err != nil {
		t.Fatalf("writeSecretFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %o, want 600 (artifact embeds a private key)", perm)
	}
}

func TestRenderWGQuickConfig(t *testing.T) {
	hub := directory.Node{Name: "gw", PublicKey: "HUBPUB", Endpoint: "vpn.example.com:51820"}
	got := renderWGQuickConfig("PRIVKEY", "10.42.0.5", "10.42.0.0/24", hub)
	want := "[Interface]\n" +
		"PrivateKey = PRIVKEY\n" +
		"Address = 10.42.0.5/32\n" +
		"\n[Peer]\n" +
		"PublicKey = HUBPUB\n" +
		"Endpoint = vpn.example.com:51820\n" +
		"AllowedIPs = 10.42.0.0/24\n" +
		"PersistentKeepalive = 25\n"
	if got != want {
		t.Fatalf("config mismatch:\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderWGQuickConfigWithPSK(t *testing.T) {
	hub := directory.Node{Name: "gw", PublicKey: "HUBPUB", Endpoint: "vpn.example.com:51820", PSK: "SECRETPSK"}
	got := renderWGQuickConfig("PRIVKEY", "10.42.0.5", "10.42.0.0/24", hub)
	if !strings.Contains(got, "PresharedKey = SECRETPSK\n") {
		t.Fatalf("expected PresharedKey line, got:\n%s", got)
	}
	// PresharedKey must sit in the [Peer] block, before Endpoint.
	if strings.Index(got, "PresharedKey") > strings.Index(got, "Endpoint") {
		t.Fatalf("PresharedKey should precede Endpoint:\n%s", got)
	}
}

func TestPeerHub(t *testing.T) {
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "self", PublicKey: "SELF", Endpoint: "1.2.3.4:51820"}, // skipped: it's self
		{Name: "laptop", PublicKey: "LAPTOP"},                        // skipped: no endpoint
		{Name: "gw", PublicKey: "GW", Endpoint: "vpn:51820"},         // first eligible
		{Name: "gw2", PublicKey: "GW2", Endpoint: "vpn2:51820"},
	}}
	hub, ok := peerHub(dir, "SELF")
	if !ok || hub.PublicKey != "GW" {
		t.Fatalf("got (%+v, %v), want GW", hub, ok)
	}

	none := directory.Directory{Nodes: []directory.Node{
		{Name: "self", PublicKey: "SELF", Endpoint: "1.2.3.4:51820"},
		{Name: "laptop", PublicKey: "LAPTOP"},
	}}
	if _, ok := peerHub(none, "SELF"); ok {
		t.Fatal("expected no hub when only self has an endpoint")
	}
}

// reconstructBitmap parses emitQRTerminal output back into a module grid so we
// can prove the half-block packing faithfully represents the encoder's bitmap.
func reconstructBitmap(t *testing.T, out string, color bool) [][]bool {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var grid [][]bool
	if color {
		// Each cell is "\x1b[38;5;{fg};48;5;{bg}m▀"; fg paints the top half,
		// bg the bottom half. 16 = dark, 231 = light.
		cell := regexp.MustCompile(`\x1b\[38;5;(\d+);48;5;(\d+)m▀`)
		for _, line := range lines {
			var top, bottom []bool
			for _, m := range cell.FindAllStringSubmatch(line, -1) {
				top = append(top, m[1] == "16")
				bottom = append(bottom, m[2] == "16")
			}
			grid = append(grid, top, bottom)
		}
		return grid
	}
	for _, line := range lines {
		var top, bottom []bool
		for _, r := range line {
			switch r {
			case '█':
				top, bottom = append(top, true), append(bottom, true)
			case '▀':
				top, bottom = append(top, true), append(bottom, false)
			case '▄':
				top, bottom = append(top, false), append(bottom, true)
			case ' ':
				top, bottom = append(top, false), append(bottom, false)
			default:
				t.Fatalf("unexpected glyph %q", r)
			}
		}
		grid = append(grid, top, bottom)
	}
	return grid
}

func TestEmitQRTerminalRoundTrip(t *testing.T) {
	content := renderWGQuickConfig(
		"oK3bF8Wc2pQ7rT5vY1nM4kJ6hG9dS0aZ8xC3bV7eR0=",
		"10.42.0.9", "10.42.0.0/24",
		directory.Node{Name: "gw", PublicKey: "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4c=", Endpoint: "vpn.example.com:51820"},
	)
	want := mustBitmap(t, content)

	for _, color := range []bool{false, true} {
		var sb strings.Builder
		if err := emitQRTerminal(&sb, content, color); err != nil {
			t.Fatalf("emitQRTerminal(color=%v): %v", color, err)
		}
		got := reconstructBitmap(t, sb.String(), color)
		// The bitmap height is odd, so the final text row carries a phantom
		// bottom half; the reconstruction has one extra all-light row.
		if len(got) < len(want) {
			t.Fatalf("color=%v: got %d rows, want >= %d", color, len(got), len(want))
		}
		for y := range want {
			if len(got[y]) != len(want[y]) {
				t.Fatalf("color=%v: row %d width %d, want %d", color, y, len(got[y]), len(want[y]))
			}
			for x := range want[y] {
				if got[y][x] != want[y][x] {
					t.Fatalf("color=%v: module (%d,%d)=%v, want %v", color, x, y, got[y][x], want[y][x])
				}
			}
		}
		for y := len(want); y < len(got); y++ {
			for x := range got[y] {
				if got[y][x] {
					t.Fatalf("color=%v: phantom row %d has a dark module at %d", color, y, x)
				}
			}
		}
	}
}

func mustBitmap(t *testing.T, content string) [][]bool {
	t.Helper()
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		t.Fatalf("qrcode.New: %v", err)
	}
	return q.Bitmap()
}
