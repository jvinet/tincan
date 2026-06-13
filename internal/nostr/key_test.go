package nostr

import (
	"encoding/hex"
	"testing"
)

// The canonical NIP-19 worked example: one keypair in all four encodings.
const (
	nip19NsecBech32 = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
	nip19PrivHex    = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"
	nip19NpubBech32 = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
	// nip19PubHex (in event_test.go) is this keypair's public key.
)

func TestNIP19Vectors(t *testing.T) {
	t.Run("nsec decodes to the known private key", func(t *testing.T) {
		sk, err := ParseSecretKey(nip19NsecBech32)
		if err != nil {
			t.Fatalf("ParseSecretKey: %v", err)
		}
		if got := hex.EncodeToString(sk.Serialize()); got != nip19PrivHex {
			t.Errorf("private key = %s, want %s", got, nip19PrivHex)
		}
		// And that key derives the known public key.
		if got := PublicKeyHex(sk); got != nip19PubHex {
			t.Errorf("derived pubkey = %s, want %s", got, nip19PubHex)
		}
	})
	t.Run("npub decodes to the known public key", func(t *testing.T) {
		if got, err := ParsePublicKey(nip19NpubBech32); err != nil || got != nip19PubHex {
			t.Errorf("ParsePublicKey(npub) = %q, %v; want %s", got, err, nip19PubHex)
		}
	})
	t.Run("hex forms pass through unchanged", func(t *testing.T) {
		if got, err := ParsePublicKey(nip19PubHex); err != nil || got != nip19PubHex {
			t.Errorf("ParsePublicKey(hex) = %q, %v; want %s", got, err, nip19PubHex)
		}
	})
	t.Run("encoding the known keys reproduces the bech32 strings", func(t *testing.T) {
		priv, _ := hex.DecodeString(nip19PrivHex)
		if got, err := encodeBech32("nsec", priv); err != nil || got != nip19NsecBech32 {
			t.Errorf("encodeBech32(nsec) = %q, %v; want %s", got, err, nip19NsecBech32)
		}
		pub, _ := hex.DecodeString(nip19PubHex)
		if got, err := encodeBech32("npub", pub); err != nil || got != nip19NpubBech32 {
			t.Errorf("encodeBech32(npub) = %q, %v; want %s", got, err, nip19NpubBech32)
		}
	})
}

func TestGenerateKeyRoundTrip(t *testing.T) {
	nsec, npub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sk, err := ParseSecretKey(nsec)
	if err != nil {
		t.Fatalf("ParseSecretKey(generated nsec): %v", err)
	}
	fromNpub, err := ParsePublicKey(npub)
	if err != nil {
		t.Fatalf("ParsePublicKey(generated npub): %v", err)
	}
	if got := PublicKeyHex(sk); got != fromNpub {
		t.Errorf("generated keypair inconsistent: nsec→%s but npub→%s", got, fromNpub)
	}
}

func TestParseKeyRejectsBad(t *testing.T) {
	bad := []string{
		"",
		"not-bech32-not-hex",
		"npub1qqqq", // too short / bad checksum
		"nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe8", // last char flipped: bad checksum
		hex.EncodeToString(make([]byte, 31)),                              // 31-byte hex: wrong length
		hex.EncodeToString(make([]byte, 33)),                              // 33-byte hex: wrong length
	}
	for _, s := range bad {
		if _, err := ParsePublicKey(s); err == nil {
			t.Errorf("ParsePublicKey(%q) succeeded, want error", s)
		}
	}
	// Wrong entity type: an npub is not a secret key, and vice versa.
	if _, err := ParseSecretKey(nip19NpubBech32); err == nil {
		t.Error("ParseSecretKey(npub) succeeded, want error")
	}
	if _, err := ParsePublicKey(nip19NsecBech32); err == nil {
		t.Error("ParsePublicKey(nsec) succeeded, want error")
	}
}

func TestBech32RoundTrip(t *testing.T) {
	for i := 0; i < 32; i++ {
		data := make([]byte, 32)
		for j := range data {
			data[j] = byte((i*7 + j*13) % 256)
		}
		enc, err := encodeBech32("npub", data)
		if err != nil {
			t.Fatalf("encodeBech32: %v", err)
		}
		hrp, dec, err := decodeBech32(enc)
		if err != nil {
			t.Fatalf("decodeBech32(%q): %v", enc, err)
		}
		if hrp != "npub" || hex.EncodeToString(dec) != hex.EncodeToString(data) {
			t.Errorf("round-trip mismatch: hrp=%q data=%x dec=%x", hrp, data, dec)
		}
	}
}
