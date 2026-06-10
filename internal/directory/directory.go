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
	AgeRecipient     string    `msgpack:"age,omitempty"`
	Endpoint         string    `msgpack:"ep,omitempty"`
	ObservedEndpoint string    `msgpack:"oep,omitempty"`
	ObservedAt       time.Time `msgpack:"oat,omitempty"`
	PSK              string    `msgpack:"psk,omitempty"`
}

type Envelope struct {
	Payload   []byte `msgpack:"p"`
	Signature []byte `msgpack:"sig"`
}
