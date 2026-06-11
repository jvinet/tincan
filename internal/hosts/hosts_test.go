package hosts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jvinet/tincan/internal/directory"
)

func sampleDir(domain string) directory.Directory {
	return directory.Directory{
		Domain: domain,
		Nodes: []directory.Node{
			{Name: "NAS", TunnelIP: "10.42.0.3"},
			{Name: "alice", TunnelIP: "10.42.0.1"},
			{Name: "phone", TunnelIP: "10.42.0.9"},
		},
	}
}

func TestBlockRendersSortedLowercaseFQDNs(t *testing.T) {
	got := Block(sampleDir("vpn"))
	want := "10.42.0.1\talice.vpn\n10.42.0.3\tnas.vpn\n10.42.0.9\tphone.vpn\n"
	if got != want {
		t.Fatalf("Block:\ngot  %q\nwant %q", got, want)
	}
	if strings.Contains(got, "\tnas\n") || strings.Contains(got, " nas\n") {
		t.Fatal("Block must not emit bare-name aliases (they shadow LAN entries)")
	}
	if Block(sampleDir("")) != "" {
		t.Fatal("Block should be empty without a domain")
	}
}

func TestApplyCreatesUpdatesRemoves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	userContent := "127.0.0.1 localhost\n192.168.1.5 nas\n"
	if err := os.WriteFile(path, []byte(userContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// First write appends the marked block after a blank line.
	changed, err := Apply(path, Block(sampleDir("vpn")))
	if err != nil || !changed {
		t.Fatalf("first apply: changed=%v err=%v", changed, err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), userContent) {
		t.Fatalf("operator content not preserved verbatim:\n%s", data)
	}
	for _, want := range []string{beginMarker, "10.42.0.3\tnas.vpn", endMarker} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %q in:\n%s", want, data)
		}
	}

	// Idempotent: same block, no write, mtime untouched.
	before, _ := os.Stat(path)
	changed, err = Apply(path, Block(sampleDir("vpn")))
	if err != nil || changed {
		t.Fatalf("idempotent apply: changed=%v err=%v", changed, err)
	}
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged apply rewrote the file")
	}

	// Update in place: a node leaves; only the block region changes.
	smaller := sampleDir("vpn")
	smaller.Nodes = smaller.Nodes[:2]
	if changed, err = Apply(path, Block(smaller)); err != nil || !changed {
		t.Fatalf("update apply: changed=%v err=%v", changed, err)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "phone.vpn") || !strings.Contains(string(data), "nas.vpn") {
		t.Fatalf("block not updated:\n%s", data)
	}
	if !strings.HasPrefix(string(data), userContent) {
		t.Fatalf("operator content disturbed by update:\n%s", data)
	}

	// Empty block removes the markers; operator content stays.
	if changed, err = Apply(path, ""); err != nil || !changed {
		t.Fatalf("removal apply: changed=%v err=%v", changed, err)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "tincan") || !strings.HasPrefix(string(data), userContent) {
		t.Fatalf("removal left traces or ate content:\n%s", data)
	}
	// Removing again is a no-op.
	if changed, err = Apply(path, ""); err != nil || changed {
		t.Fatalf("second removal: changed=%v err=%v", changed, err)
	}
}

func TestApplyMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	// Missing file + empty block: nothing to do, no file created.
	if changed, err := Apply(path, ""); err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty apply created a file")
	}
	// Missing file + block: created 0644 with just the marked block.
	if changed, err := Apply(path, "10.42.0.1\talice.vpn\n"); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("created mode %04o, want 0644", st.Mode().Perm())
	}
}

func TestApplyPreservesMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(path, "10.42.0.1\talice.vpn\n"); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o not preserved, want 0600", st.Mode().Perm())
	}
}

func TestApplyRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-hosts")
	if err := os.WriteFile(target, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hosts")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(link, "10.42.0.1\talice.vpn\n"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("err=%v, want ErrSymlink", err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "127.0.0.1 localhost\n" {
		t.Fatalf("symlink target was touched:\n%s", data)
	}
}

func TestRewriteMalformedMarkers(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{name: "begin only", content: "x\n" + beginMarker + "\nstuff\n"},
		{name: "end only", content: "x\n" + endMarker + "\n"},
		{name: "end before begin", content: endMarker + "\n" + beginMarker + "\n"},
		{name: "double begin", content: beginMarker + "\n" + beginMarker + "\n" + endMarker + "\n"},
		{name: "double end", content: beginMarker + "\n" + endMarker + "\n" + endMarker + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Rewrite([]byte(tc.content), "10.42.0.1\ta.vpn\n"); !errors.Is(err, ErrMalformedMarkers) {
				t.Fatalf("err=%v, want ErrMalformedMarkers", err)
			}
		})
	}
}

func TestRewritePreservesContentAfterBlock(t *testing.T) {
	content := "before\n" + beginMarker + "\nold\n" + endMarker + "\nafter\n"
	got, changed, err := Rewrite([]byte(content), "new\n")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	want := "before\n" + beginMarker + "\nnew\n" + endMarker + "\nafter\n"
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRewriteHandlesNoTrailingNewline(t *testing.T) {
	got, changed, err := Rewrite([]byte("127.0.0.1 localhost"), "10.42.0.1\ta.vpn\n")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	want := "127.0.0.1 localhost\n\n" + beginMarker + "\n10.42.0.1\ta.vpn\n" + endMarker + "\n"
	if string(got) != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}
