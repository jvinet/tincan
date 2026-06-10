package directory

import "time"

// SchemaVersion 2 replaced the single shared age identity with per-node
// recipients: the directory is encrypted to every member's AgeRecipient, so
// removing a node and republishing cryptographically revokes its access. v1
// blobs (one shared recipient) are not forward-compatible and are rejected.
const SchemaVersion uint32 = 2

type Directory struct {
	SchemaVersion uint32    `msgpack:"v"`
	Serial        uint64    `msgpack:"s"`
	CreatedAt     time.Time `msgpack:"t"`
	NetworkCIDR   string    `msgpack:"cidr"`
	Nodes         []Node    `msgpack:"nodes"`
}

type Node struct {
	Name      string `msgpack:"n"`
	PublicKey string `msgpack:"pk"`
	TunnelIP  string `msgpack:"ip"`
	// AgeRecipient is the node's age public key (age1…). The directory is
	// sealed to the recipients of all members that have one, so each node
	// decrypts with its own identity. Empty for plain-WireGuard members,
	// which don't run Tincan and never read the directory.
	AgeRecipient string `msgpack:"age,omitempty"`
	Endpoint     string `msgpack:"ep,omitempty"`
	// Relay marks this node as a designated relay: peers that can't reach a
	// destination directly route through it. When any node sets this, relay
	// selection prefers the marked node(s) over the implicit "first node with
	// an endpoint" fallback, making the relay path intentional rather than
	// dependent on directory order. A relay must also publish an Endpoint —
	// a node with no reachable address can't carry anyone's traffic.
	Relay            bool      `msgpack:"relay,omitempty"`
	ObservedEndpoint string    `msgpack:"oep,omitempty"`
	ObservedAt       time.Time `msgpack:"oat,omitempty"`
	PSK              string    `msgpack:"psk,omitempty"`
}

// IsPlainWireGuard reports whether the node is a plain WireGuard member
// (enrolled with `add-node --client-type=wireguard`): it runs no Tincan daemon
// and carries no AgeRecipient because it never reads the directory. Its
// enrolled config is hub-and-spoke — the only peer it knows is its hub (the
// RelayTarget at enrollment time) — so it never initiates handshakes to other
// members and silently drops theirs as coming from unknown keys.
func (n Node) IsPlainWireGuard() bool {
	return n.AgeRecipient == ""
}

type Envelope struct {
	Payload   []byte `msgpack:"p"`
	Signature []byte `msgpack:"sig"`
}

// RelayTarget returns the node that peers should route through when a direct
// path to a destination is unavailable, and whether such a node exists.
//
// A relay must publish a reachable Endpoint — a node with no address can't
// carry anyone's traffic, so endpoint-less nodes are never selected (even if
// flagged). Among reachable nodes, those explicitly marked Relay win, in
// directory order; if none are marked, the first reachable non-self node is
// used, preserving the original "first node with an endpoint" behavior so a
// directory that sets no roles relays exactly as before.
//
// selfPubKey is excluded so a node never picks itself; pass "" to consider
// every node — e.g. choosing a hub for a plain-WireGuard client that is not
// yet (or never will be) in the directory.
func RelayTarget(dir Directory, selfPubKey string) (Node, bool) {
	fallback := -1
	for i := range dir.Nodes {
		n := dir.Nodes[i]
		if n.PublicKey == selfPubKey || n.Endpoint == "" {
			continue
		}
		if n.Relay {
			return n, true
		}
		if fallback < 0 {
			fallback = i
		}
	}
	if fallback >= 0 {
		return dir.Nodes[fallback], true
	}
	return Node{}, false
}
