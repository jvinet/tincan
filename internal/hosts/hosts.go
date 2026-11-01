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
	"syscall"

	"github.com/google/renameio/v2"
	"github.com/jvinet/tincan/internal/directory"
)

// DefaultPath is the hosts file the managed block lives in unless the
// [dns] hosts_path config overrides it.
const DefaultPath = "/etc/hosts"

const (
	legacyBeginMarker = "# BEGIN tincan managed block - do not edit between markers"
	legacyEndMarker   = "# END tincan managed block"
	legacyInterface   = "tincan0"
)

// ErrMalformedMarkers reports a hosts file whose tincan markers are not
// properly ordered, non-nested begin/end pairs, at most one per interface.
// Rewriting around ambiguous markers risks eating operator content out of
// /etc/hosts — the one unrecoverable failure
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

// Apply rewrites the hosts file at path so iface's managed block matches block,
// atomically and preserving the file's mode and other interfaces' blocks. An
// empty block removes only iface's marker pair. Reports changed=false without
// writing when the file already matches. A persistent sibling .tincan.lock file
// serializes read-modify-write across daemons; locking the hosts file itself
// would not survive its atomic replacement.
func Apply(path, iface, block string) (changed bool, err error) {
	lock, err := os.OpenFile(path+".tincan.lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return false, fmt.Errorf("open hosts lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return false, fmt.Errorf("lock hosts file: %w", err)
	}
	// Closing releases the lock. Never unlink it: waiters must share one inode.
	st, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if block == "" {
			return false, nil
		}
		content, _, err := Rewrite(nil, iface, block)
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
	content, changed, err := Rewrite(original, iface, block)
	if err != nil || !changed {
		return false, err
	}
	return true, renameio.WriteFile(path, content, st.Mode().Perm())
}

// Rewrite is Apply's pure core: it returns content with iface's managed block
// replaced by block (inserted at EOF when absent, removed when block is
// empty), preserving every byte outside that marker pair. Legacy unlabelled
// markers belong to tincan0 and are migrated to labelled markers on update.
// changed is false when the result equals the input. Status uses it read-only.
func Rewrite(content []byte, iface, block string) (result []byte, changed bool, err error) {
	before, after, found, err := splitAtMarkers(content, iface)
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
		writeMarkedBlock(&out, iface, block)
		out.Write(after)
	default:
		out.Write(content)
		if len(content) > 0 && !bytes.HasSuffix(content, []byte("\n")) {
			out.WriteByte('\n')
		}
		if len(content) > 0 {
			out.WriteByte('\n') // one blank line between operator content and ours
		}
		writeMarkedBlock(&out, iface, block)
	}
	result = out.Bytes()
	return result, !bytes.Equal(result, content), nil
}

func beginMarker(iface string) string {
	return "# BEGIN tincan managed block (" + iface + ") - do not edit between markers"
}

func endMarker(iface string) string {
	return "# END tincan managed block (" + iface + ")"
}

func writeMarkedBlock(out *bytes.Buffer, iface, block string) {
	out.WriteString(beginMarker(iface))
	out.WriteByte('\n')
	out.WriteString(block) // Block always ends with \n
	out.WriteString(endMarker(iface))
	out.WriteByte('\n')
}

// marker identifies whole, whitespace-trimmed marker lines. Unlabelled
// markers are aliases for tincan0, not a block owned by every interface.
func marker(line string) (iface string, begin, ok bool) {
	switch line {
	case legacyBeginMarker:
		return legacyInterface, true, true
	case legacyEndMarker:
		return legacyInterface, false, true
	}
	if rest, ok := strings.CutPrefix(line, "# BEGIN tincan managed block ("); ok {
		iface, ok = strings.CutSuffix(rest, ") - do not edit between markers")
		return iface, true, ok && iface != ""
	}
	if rest, ok := strings.CutPrefix(line, "# END tincan managed block ("); ok {
		iface, ok = strings.CutSuffix(rest, ")")
		return iface, false, ok && iface != ""
	}
	return "", false, false
}

// splitAtMarkers returns the bytes outside iface's marker pair. Validate all
// recognized pairs so a mismatched or nested block cannot swallow another
// network's entries or operator content.
func splitAtMarkers(content []byte, iface string) (before, after []byte, found bool, err error) {
	beginAt, endAt := -1, -1
	seen := make(map[string]bool)
	open := ""
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
		if owner, begin, ok := marker(string(bytes.TrimSpace(line))); ok {
			if begin {
				if open != "" || seen[owner] {
					return nil, nil, false, ErrMalformedMarkers
				}
				open = owner
				seen[owner] = true
				if owner == iface {
					beginAt = offset
				}
			} else {
				if open != owner {
					return nil, nil, false, ErrMalformedMarkers
				}
				open = ""
				if owner == iface {
					endAt = offset + lineLen
				}
			}
		}
		offset += lineLen
		rest = rest[lineLen:]
	}
	if open != "" {
		return nil, nil, false, ErrMalformedMarkers
	}
	if beginAt < 0 {
		return nil, nil, false, nil
	}
	return content[:beginAt], content[endAt:], true, nil
}
