package nostr

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// SignEvent fills in e.PubKey (derived from sk), e.ID, and e.Sig, signing the
// event's canonical serialization with BIP-340 schnorr. The caller must have set
// CreatedAt, Kind, Tags, and Content first, since the id commits to them.
func SignEvent(e *Event, sk *btcec.PrivateKey) error {
	e.PubKey = PublicKeyHex(sk)
	sum := e.idBytes()
	e.ID = hex.EncodeToString(sum[:])
	sig, err := schnorr.Sign(sk, sum[:])
	if err != nil {
		return fmt.Errorf("schnorr sign: %w", err)
	}
	e.Sig = hex.EncodeToString(sig.Serialize())
	return nil
}

// PublicKeyHex returns the 32-byte x-only public key (hex) for sk — the form
// Nostr events carry in the "pubkey" field. The compressed encoding is 33 bytes
// (a parity prefix followed by the x coordinate); BIP-340/Nostr use only x.
func PublicKeyHex(sk *btcec.PrivateKey) string {
	return hex.EncodeToString(sk.PubKey().SerializeCompressed()[1:])
}

// GenerateKey creates a fresh secp256k1 keypair and returns it bech32-encoded as
// (nsec, npub) per NIP-19 — the forms an operator pastes into config or that
// `tincan init` emits.
func GenerateKey() (nsec, npub string, err error) {
	sk, err := btcec.NewPrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	nsec, err = encodeBech32("nsec", sk.Serialize())
	if err != nil {
		return "", "", err
	}
	npub, err = encodeBech32("npub", sk.PubKey().SerializeCompressed()[1:])
	if err != nil {
		return "", "", err
	}
	return nsec, npub, nil
}

// ParseSecretKey accepts a 64-char hex secret key or an "nsec1…" bech32 string
// and returns the secp256k1 private key.
func ParseSecretKey(s string) (*btcec.PrivateKey, error) {
	raw, err := decodeKeyMaterial(strings.TrimSpace(s), "nsec")
	if err != nil {
		return nil, err
	}
	sk, _ := btcec.PrivKeyFromBytes(raw)
	return sk, nil
}

// ParsePublicKey accepts a 64-char hex x-only pubkey or an "npub1…" bech32 string
// and returns the canonical lowercase 32-byte hex form used in events. It rejects
// material that is not a valid x-only curve point so a mistyped key fails at
// config time rather than at the first verify.
func ParsePublicKey(s string) (string, error) {
	raw, err := decodeKeyMaterial(strings.TrimSpace(s), "npub")
	if err != nil {
		return "", err
	}
	if _, err := schnorr.ParsePubKey(raw); err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// decodeKeyMaterial decodes s as either the bech32 entity named by wantHRP or as
// 32-byte hex, returning the raw 32 bytes.
func decodeKeyMaterial(s, wantHRP string) ([]byte, error) {
	var raw []byte
	if strings.HasPrefix(s, wantHRP+"1") {
		hrp, data, err := decodeBech32(s)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", wantHRP, err)
		}
		if hrp != wantHRP {
			return nil, fmt.Errorf("expected %s, got bech32 prefix %q", wantHRP, hrp)
		}
		raw = data
	} else {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("key is neither %s nor hex: %w", wantHRP, err)
		}
		raw = b
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}
