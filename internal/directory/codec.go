package directory

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"filippo.io/age"
	"github.com/jvinet/tincan/internal/keys"
	"github.com/vmihailenco/msgpack/v5"
)

// Stamp returns the current time at the precision directory timestamps are
// persisted with: whole seconds, in UTC. msgpack encodes a second-precision
// time.Time as a 6-byte timestamp32 extension, versus the 10-byte timestamp64
// it must use once sub-second digits are present. Nothing in tincan reads
// sub-second precision off these fields — Serial (not CreatedAt) is the
// freshness signal, and ObservedAt is only ever displayed rounded — so every
// CreatedAt/ObservedAt write goes through this to keep them at the compact
// width. Do not "tidy" the Truncate away.
func Stamp() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

func MarshalPlain(dir Directory) ([]byte, error) {
	dir.SchemaVersion = SchemaVersion
	if dir.CreatedAt.IsZero() {
		dir.CreatedAt = Stamp()
	} else {
		dir.CreatedAt = dir.CreatedAt.UTC()
	}
	if err := Validate(dir); err != nil {
		return nil, err
	}
	return msgpack.Marshal(dir)
}

func UnmarshalPlain(data []byte) (Directory, error) {
	var dir Directory
	if err := msgpack.Unmarshal(data, &dir); err != nil {
		return Directory{}, fmt.Errorf("decode directory: %w", err)
	}
	if err := Validate(dir); err != nil {
		return Directory{}, err
	}
	return dir, nil
}

// wireNode is the on-the-wire form of Node. It differs only in that key
// material and the tunnel IP are stored as raw bytes instead of the base64 /
// dotted-decimal strings Node carries in memory: a WireGuard key is 32 bytes
// (~34 on the wire) versus 44 base64 chars (~46), and an IPv4 address is 4
// bytes versus a ~10-char string — about 16 bytes/node off the sealed
// directory. Node converts to and from this form in its msgpack hooks, so the
// rest of tincan keeps working with the string fields. The msgpack tags
// (names + omitempty) match Node's exactly, preserving the field-omission
// behavior; only pk/ip/psk change representation.
type wireNode struct {
	Name             string    `msgpack:"n"`
	PublicKey        []byte    `msgpack:"pk"`
	TunnelIP         []byte    `msgpack:"ip"`
	Endpoint         string    `msgpack:"ep,omitempty"`
	ObservedEndpoint string    `msgpack:"oep,omitempty"`
	ObservedAt       time.Time `msgpack:"oat,omitempty"`
	PSK              []byte    `msgpack:"psk,omitempty"`
}

// EncodeMsgpack implements msgpack.CustomEncoder so every Node is written in
// the compact wireNode form. msgpack.Marshal invokes it per element of
// Directory.Nodes; DecodeMsgpack is the inverse.
func (n Node) EncodeMsgpack(enc *msgpack.Encoder) error {
	w, err := n.toWire()
	if err != nil {
		return err
	}
	return enc.Encode(w)
}

func (n *Node) DecodeMsgpack(dec *msgpack.Decoder) error {
	var w wireNode
	if err := dec.Decode(&w); err != nil {
		return err
	}
	return n.fromWire(w)
}

func (n Node) toWire() (wireNode, error) {
	pk, err := keys.WGKeyToBytes(n.PublicKey)
	if err != nil {
		return wireNode{}, fmt.Errorf("encode node %q: %w", n.Name, err)
	}
	ip, err := netip.ParseAddr(n.TunnelIP)
	if err != nil || !ip.Is4() {
		return wireNode{}, fmt.Errorf("encode node %q: tunnel IP %q is not IPv4", n.Name, n.TunnelIP)
	}
	ip4 := ip.As4()
	w := wireNode{
		Name:             n.Name,
		PublicKey:        pk,
		TunnelIP:         ip4[:],
		Endpoint:         n.Endpoint,
		ObservedEndpoint: n.ObservedEndpoint,
		ObservedAt:       n.ObservedAt,
	}
	if n.PSK != "" {
		psk, err := keys.WGKeyToBytes(n.PSK)
		if err != nil {
			return wireNode{}, fmt.Errorf("encode node %q PSK: %w", n.Name, err)
		}
		w.PSK = psk
	}
	return w, nil
}

func (n *Node) fromWire(w wireNode) error {
	pk, err := keys.WGKeyFromBytes(w.PublicKey)
	if err != nil {
		return fmt.Errorf("decode node %q: %w", w.Name, err)
	}
	if len(w.TunnelIP) != 4 {
		return fmt.Errorf("decode node %q: tunnel IP is %d bytes, want 4", w.Name, len(w.TunnelIP))
	}
	ip4 := [4]byte{w.TunnelIP[0], w.TunnelIP[1], w.TunnelIP[2], w.TunnelIP[3]}
	n.Name = w.Name
	n.PublicKey = pk
	n.TunnelIP = netip.AddrFrom4(ip4).String()
	n.Endpoint = w.Endpoint
	n.ObservedEndpoint = w.ObservedEndpoint
	n.ObservedAt = w.ObservedAt
	n.PSK = ""
	if len(w.PSK) > 0 {
		psk, err := keys.WGKeyFromBytes(w.PSK)
		if err != nil {
			return fmt.Errorf("decode node %q PSK: %w", w.Name, err)
		}
		n.PSK = psk
	}
	return nil
}

func Seal(dir Directory, networkIdentity string, publisherPrivateKey string) ([]byte, error) {
	payload, err := MarshalPlain(dir)
	if err != nil {
		return nil, err
	}
	identity, err := keys.ParseAgeIdentity(networkIdentity)
	if err != nil {
		return nil, err
	}
	publisherKey, err := keys.DecodeEd25519Private(publisherPrivateKey)
	if err != nil {
		return nil, err
	}
	envelope := Envelope{
		Payload:   payload,
		Signature: ed25519.Sign(publisherKey, payload),
	}
	envelopeBytes, err := msgpack.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode directory envelope: %w", err)
	}
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, identity.Recipient())
	if err != nil {
		return nil, fmt.Errorf("start age encryption: %w", err)
	}
	if _, err := w.Write(envelopeBytes); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("write age payload: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finish age encryption: %w", err)
	}
	return encrypted.Bytes(), nil
}

func Open(blob []byte, networkIdentity string, publisherPublicKey string) (Directory, []byte, error) {
	identity, err := keys.ParseAgeIdentity(networkIdentity)
	if err != nil {
		return Directory{}, nil, err
	}
	publisherKey, err := keys.DecodeEd25519Public(publisherPublicKey)
	if err != nil {
		return Directory{}, nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(blob), identity)
	if err != nil {
		return Directory{}, nil, fmt.Errorf("decrypt directory: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return Directory{}, nil, fmt.Errorf("read decrypted directory: %w", err)
	}
	var envelope Envelope
	if err := msgpack.Unmarshal(plaintext, &envelope); err != nil {
		return Directory{}, nil, fmt.Errorf("decode directory envelope: %w", err)
	}
	if len(envelope.Payload) == 0 || len(envelope.Signature) == 0 {
		return Directory{}, nil, errors.New("directory envelope missing payload or signature")
	}
	if !ed25519.Verify(publisherKey, envelope.Payload, envelope.Signature) {
		return Directory{}, nil, errors.New("directory signature verification failed")
	}
	dir, err := UnmarshalPlain(envelope.Payload)
	if err != nil {
		return Directory{}, nil, err
	}
	return dir, envelope.Payload, nil
}

func Validate(dir Directory) error {
	if dir.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported directory schema version %d", dir.SchemaVersion)
	}
	prefix, err := netip.ParsePrefix(dir.NetworkCIDR)
	if err != nil {
		return fmt.Errorf("invalid network CIDR: %w", err)
	}
	prefix = prefix.Masked()
	seenNames := make(map[string]struct{}, len(dir.Nodes))
	seenIPs := make(map[string]struct{}, len(dir.Nodes))
	seenKeys := make(map[string]struct{}, len(dir.Nodes))
	for _, node := range dir.Nodes {
		if node.Name == "" {
			return errors.New("directory contains node with empty name")
		}
		if _, ok := seenNames[node.Name]; ok {
			return fmt.Errorf("duplicate node name %q", node.Name)
		}
		seenNames[node.Name] = struct{}{}
		if _, err := keys.ParseWGPublic(node.PublicKey); err != nil {
			return fmt.Errorf("node %q has invalid WireGuard public key: %w", node.Name, err)
		}
		if _, ok := seenKeys[node.PublicKey]; ok {
			return fmt.Errorf("duplicate node public key for %q", node.Name)
		}
		seenKeys[node.PublicKey] = struct{}{}
		ip, err := netip.ParseAddr(node.TunnelIP)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("node %q has invalid IPv4 tunnel IP", node.Name)
		}
		if !prefix.Contains(ip) {
			return fmt.Errorf("node %q tunnel IP %s is outside %s", node.Name, node.TunnelIP, dir.NetworkCIDR)
		}
		if _, ok := seenIPs[node.TunnelIP]; ok {
			return fmt.Errorf("duplicate tunnel IP %q", node.TunnelIP)
		}
		seenIPs[node.TunnelIP] = struct{}{}
	}
	return nil
}
