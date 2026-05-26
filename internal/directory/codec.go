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

func MarshalPlain(dir Directory) ([]byte, error) {
	dir.SchemaVersion = SchemaVersion
	if dir.CreatedAt.IsZero() {
		dir.CreatedAt = time.Now().UTC()
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
