package directory

import (
	"strings"
	"time"
)

// Diff summarizes how one directory revision differs from another. It exists
// for operator-facing logging — to answer "what changed to justify this
// republish?" without dumping the whole directory. Nodes are matched by public
// key (the stable cryptographic identity), so a rename shows up as a "name"
// field change rather than an add+remove. Secret material (PSKs) is reported as
// a state transition only, never by value.
type Diff struct {
	OldSerial uint64
	NewSerial uint64
	CIDR      *FieldChange // network CIDR change, if any
	Added     []string     // display names present only in the new revision
	Removed   []string     // display names present only in the old revision
	Changed   []NodeDiff   // nodes present in both revisions whose fields differ
}

// NodeDiff holds the per-field changes for a single node present in both
// revisions.
type NodeDiff struct {
	Name   string
	Fields []FieldChange
}

// FieldChange describes a single field's transition. Detail is a
// human-readable rendering (e.g. "1.2.3.4:51820 -> 5.6.7.8:33001",
// "refreshed (+15m0s)", "cleared").
type FieldChange struct {
	Field  string
	Detail string
}

// Compare reports the differences between two directory revisions. Serial and
// CreatedAt are intentionally ignored at the field level: they change on every
// bump and carry no routing meaning. The serials are surfaced separately via
// OldSerial/NewSerial.
func Compare(oldDir, newDir Directory) Diff {
	d := Diff{OldSerial: oldDir.Serial, NewSerial: newDir.Serial}
	if oldDir.NetworkCIDR != newDir.NetworkCIDR {
		d.CIDR = &FieldChange{Field: "network_cidr", Detail: transition(oldDir.NetworkCIDR, newDir.NetworkCIDR)}
	}

	oldByKey := make(map[string]Node, len(oldDir.Nodes))
	for _, n := range oldDir.Nodes {
		oldByKey[n.PublicKey] = n
	}
	newByKey := make(map[string]Node, len(newDir.Nodes))
	for _, n := range newDir.Nodes {
		newByKey[n.PublicKey] = n
	}

	for _, n := range newDir.Nodes {
		prev, ok := oldByKey[n.PublicKey]
		if !ok {
			d.Added = append(d.Added, displayName(n))
			continue
		}
		if fields := nodeFieldChanges(prev, n); len(fields) > 0 {
			d.Changed = append(d.Changed, NodeDiff{Name: displayName(n), Fields: fields})
		}
	}
	for _, n := range oldDir.Nodes {
		if _, ok := newByKey[n.PublicKey]; !ok {
			d.Removed = append(d.Removed, displayName(n))
		}
	}
	return d
}

// Empty reports whether the two revisions are equivalent in every field this
// diff tracks (i.e. only serial/CreatedAt may differ).
func (d Diff) Empty() bool {
	return d.CIDR == nil && len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Summary renders the diff as a compact, single-line, log-friendly string.
func (d Diff) Summary() string {
	if d.Empty() {
		return "metadata only (serial/timestamp)"
	}
	var parts []string
	if d.CIDR != nil {
		parts = append(parts, d.CIDR.Field+" "+d.CIDR.Detail)
	}
	if len(d.Added) > 0 {
		parts = append(parts, "added "+strings.Join(d.Added, ", "))
	}
	if len(d.Removed) > 0 {
		parts = append(parts, "removed "+strings.Join(d.Removed, ", "))
	}
	for _, nd := range d.Changed {
		fieldParts := make([]string, 0, len(nd.Fields))
		for _, f := range nd.Fields {
			fieldParts = append(fieldParts, f.Field+" "+f.Detail)
		}
		parts = append(parts, nd.Name+": "+strings.Join(fieldParts, ", "))
	}
	return strings.Join(parts, "; ")
}

func nodeFieldChanges(oldN, newN Node) []FieldChange {
	var fields []FieldChange
	if oldN.Name != newN.Name {
		fields = append(fields, FieldChange{Field: "name", Detail: transition(oldN.Name, newN.Name)})
	}
	if oldN.TunnelIP != newN.TunnelIP {
		fields = append(fields, FieldChange{Field: "tunnel_ip", Detail: transition(oldN.TunnelIP, newN.TunnelIP)})
	}
	if oldN.Endpoint != newN.Endpoint {
		fields = append(fields, FieldChange{Field: "endpoint", Detail: transition(oldN.Endpoint, newN.Endpoint)})
	}
	switch {
	case oldN.ObservedEndpoint != newN.ObservedEndpoint:
		fields = append(fields, FieldChange{Field: "observed_endpoint", Detail: transition(oldN.ObservedEndpoint, newN.ObservedEndpoint)})
	case !oldN.ObservedAt.Equal(newN.ObservedAt):
		// Endpoint identical but the observation timestamp advanced: this is
		// the periodic refresh re-stamping a still-current observation. It
		// bumps the serial without changing any routing.
		fields = append(fields, observedAtRefresh(oldN.ObservedAt, newN.ObservedAt))
	}
	if oldN.PSK != newN.PSK {
		fields = append(fields, FieldChange{Field: "psk", Detail: secretTransition(oldN.PSK, newN.PSK)})
	}
	return fields
}

func observedAtRefresh(oldAt, newAt time.Time) FieldChange {
	if oldAt.IsZero() {
		return FieldChange{Field: "observed_at", Detail: "recorded"}
	}
	delta := newAt.Sub(oldAt)
	if delta < 0 {
		// New observation predates the old one (clock skew / rollback); report
		// the absolute step without a misleading sign.
		delta = -delta
	}
	return FieldChange{Field: "observed_at", Detail: "refreshed (+" + delta.Round(time.Second).String() + ")"}
}

// transition renders an old->new value change, substituting "(none)" for empty
// strings so cleared and newly-set fields read naturally.
func transition(oldVal, newVal string) string {
	return orNone(oldVal) + " -> " + orNone(newVal)
}

// secretTransition describes a secret field's change without ever revealing the
// value.
func secretTransition(oldVal, newVal string) string {
	switch {
	case oldVal == "" && newVal != "":
		return "set"
	case oldVal != "" && newVal == "":
		return "cleared"
	default:
		return "changed"
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func displayName(n Node) string {
	if n.Name != "" {
		return n.Name
	}
	if len(n.PublicKey) > 8 {
		return n.PublicKey[:8] + "..."
	}
	if n.PublicKey != "" {
		return n.PublicKey
	}
	return "(unknown)"
}
