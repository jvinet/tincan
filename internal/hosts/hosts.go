// Package hosts maintains tincan's managed block in a hosts file: the lines
// between a marker pair that map every directory node's <name>.<domain> to
// its tunnel IP. Members resolve VPN names entirely from this block — no DNS
// server, no resolver reconfiguration — and it keeps working from the cached
// directory when the drop (or the daemon) is down.
//
// Entries are FQDN-only, deliberately: machines often already map bare
// hostnames ("nas") to direct LAN addresses in /etc/hosts, and the managed
// block must never shadow or fight those. Plain-WireGuard spokes get bare
// names via the search domain in their rendered configs instead.
package hosts

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/google/renameio/v2"
	"github.com/jvinet/tincan/internal/directory"
)

// DefaultPath is the hosts file the managed block lives in unless the
// [dns] hosts_path config overrides it.
const DefaultPath = "/etc/hosts"

const (
	beginMarker = "# BEGIN tincan managed block - do not edit between markers"
	endMarker   = "# END tincan managed block"
)

// ErrMalformedMarkers reports a hosts file whose tincan markers are not a
// single begin/end pair in order. Rewriting around ambiguous markers risks
// eating operator content out of /etc/hosts — the one unrecoverable failure
// mode — so the file is left untouched and the caller warns.
var ErrMalformedMarkers = errors.New("hosts file has malformed tincan markers; remove the markers (and anything tincan wrote between them) by hand")

// ErrSymlink reports a hosts file that is a symbolic link (e.g. NixOS, where
// /etc/hosts points into the store). An atomic rename would replace the link
// with a regular file — exactly wrong there — so the file is left untouched.
var ErrSymlink = errors.New("hosts file is a symlink; refusing to replace it (set [dns] manage_hosts = false to silence)")

// Block renders the managed entry lines (no markers) for dir: one
// "<tunnel-ip>\t<name>.<domain>" line per node, lowercased and sorted by
// name. Every node is included — members, plain-WireGuard spokes, and self.
// Returns "" when dir carries no domain, which Apply treats as "remove the
// block".
func Block(dir directory.Directory) string {
	if dir.Domain == "" || len(dir.Nodes) == 0 {
		return ""
	}
	names := make([]string, 0, len(dir.Nodes))
	ipByName := make(map[string]string, len(dir.Nodes))
	for _, node := range dir.Nodes {
		name := strings.ToLower(node.Name)
		names = append(names, name)
		ipByName[name] = node.TunnelIP
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s\t%s.%s\n", ipByName[name], name, dir.Domain)
	}
	return b.String()
}

// Apply rewrites the hosts file at path so its managed block matches block,
// atomically and preserving the file's mode. An empty block removes the
// marker pair entirely. Reports changed=false without writing when the file
// already matches — the daemon calls this every sync interval, and an
// unchanged /etc/hosts must not churn.
func Apply(path, block string) (changed bool, err error) {
	st, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if block == "" {
			return false, nil
		}
		content, _, err := Rewrite(nil, block)
		if err != nil {
			return false, err
		}
		return true, renameio.WriteFile(path, content, 0o644)
	case err != nil:
		return false, err
	case st.Mode()&os.ModeSymlink != 0:
		return false, ErrSymlink
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	content, changed, err := Rewrite(original, block)
	if err != nil || !changed {
		return false, err
	}
	return true, renameio.WriteFile(path, content, st.Mode().Perm())
}

// Rewrite is Apply's pure core: it returns content with its managed block
// replaced by block (inserted at EOF when absent, removed when block is
// empty), preserving every byte outside the marker pair. changed is false
// when the result equals the input. Status uses it read-only to report
// whether the file is up to date.
func Rewrite(content []byte, block string) (result []byte, changed bool, err error) {
	before, after, found, err := splitAtMarkers(content)
	if err != nil {
		return nil, false, err
	}
	var out bytes.Buffer
	switch {
	case block == "" && !found:
		return content, false, nil
	case block == "":
		out.Write(before)
		out.Write(after)
	case found:
		out.Write(before)
		writeMarkedBlock(&out, block)
		out.Write(after)
	default:
		out.Write(content)
		if len(content) > 0 && !bytes.HasSuffix(content, []byte("\n")) {
			out.WriteByte('\n')
		}
		if len(content) > 0 {
			out.WriteByte('\n') // one blank line between operator content and ours
		}
		writeMarkedBlock(&out, block)
	}
	result = out.Bytes()
	return result, !bytes.Equal(result, content), nil
}

func writeMarkedBlock(out *bytes.Buffer, block string) {
	out.WriteString(beginMarker)
	out.WriteByte('\n')
	out.WriteString(block) // Block always ends with \n
	out.WriteString(endMarker)
	out.WriteByte('\n')
}

// splitAtMarkers returns the bytes strictly before the begin-marker line and
// strictly after the end-marker line. Markers are matched as whole
// (whitespace-trimmed) lines; anything but exactly one begin followed by one
// end is ErrMalformedMarkers.
func splitAtMarkers(content []byte) (before, after []byte, found bool, err error) {
	beginAt, endAt := -1, -1
	offset := 0
	rest := content
	for len(rest) > 0 {
		line := rest
		nl := bytes.IndexByte(rest, '\n')
		lineLen := len(rest)
		if nl >= 0 {
			line = rest[:nl]
			lineLen = nl + 1
		}
		switch string(bytes.TrimSpace(line)) {
		case beginMarker:
			if beginAt >= 0 {
				return nil, nil, false, ErrMalformedMarkers
			}
			beginAt = offset
		case endMarker:
			if endAt >= 0 || beginAt < 0 {
				return nil, nil, false, ErrMalformedMarkers
			}
			endAt = offset + lineLen
		}
		offset += lineLen
		rest = rest[lineLen:]
	}
	switch {
	case beginAt < 0 && endAt < 0:
		return nil, nil, false, nil
	case beginAt >= 0 && endAt < 0:
		return nil, nil, false, ErrMalformedMarkers
	}
	return content[:beginAt], content[endAt:], true, nil
}
