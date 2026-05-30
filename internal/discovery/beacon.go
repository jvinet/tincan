package discovery

import (
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

// BeaconSchemaVersion identifies the wire format. V1 receivers must tolerate
// future versions by ignoring unknown fields (msgpack handles this natively).
const BeaconSchemaVersion uint32 = 1

// Beacon is the on-the-wire announcement broadcast on the LAN multicast
// groups. See spec/lan-discovery.md § "Beacon format".
type Beacon struct {
	V         uint32 `msgpack:"v"`
	PublicKey string `msgpack:"pk"`
	Port      uint16 `msgpack:"port"`
	Nonce     uint64 `msgpack:"n"`
}

// Encode marshals a beacon for transmission.
func Encode(b Beacon) ([]byte, error) {
	if b.V == 0 {
		b.V = BeaconSchemaVersion
	}
	return msgpack.Marshal(b)
}

// Decode parses a received beacon. Returns an error for malformed input or
// schema version 0 (which is reserved as "unset").
func Decode(data []byte) (Beacon, error) {
	var b Beacon
	if err := msgpack.Unmarshal(data, &b); err != nil {
		return Beacon{}, fmt.Errorf("decode beacon: %w", err)
	}
	if b.V == 0 {
		return Beacon{}, fmt.Errorf("decode beacon: missing schema version")
	}
	if b.PublicKey == "" {
		return Beacon{}, fmt.Errorf("decode beacon: missing public_key")
	}
	if b.Port == 0 {
		return Beacon{}, fmt.Errorf("decode beacon: missing port")
	}
	return b, nil
}
