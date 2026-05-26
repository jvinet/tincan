package keys

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestGenerateAndParseWGKeypair(t *testing.T) {
	priv, pub, err := GenerateWGKeypair()
	if err != nil {
		t.Fatalf("GenerateWGKeypair: %v", err)
	}
	if priv == "" || pub == "" {
		t.Fatal("empty WireGuard key returned")
	}
	if priv == pub {
		t.Fatal("private key equals public key")
	}

	parsedPriv, err := ParseWGPrivate(priv)
	if err != nil {
		t.Fatalf("ParseWGPrivate: %v", err)
	}
	if parsedPriv.PublicKey().String() != pub {
		t.Fatalf("derived public key mismatch: got %s want %s", parsedPriv.PublicKey().String(), pub)
	}

	if _, err := ParseWGPublic(pub); err != nil {
		t.Fatalf("ParseWGPublic: %v", err)
	}
	derived, err := PublicKeyFromWGPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromWGPrivate: %v", err)
	}
	if derived != pub {
		t.Fatalf("PublicKeyFromWGPrivate mismatch: got %s want %s", derived, pub)
	}
}

func TestParseWGRejectsGarbage(t *testing.T) {
	if _, err := ParseWGPrivate("not base64!!"); err == nil {
		t.Fatal("expected invalid private key error")
	}
	if _, err := ParseWGPublic("AAAAAAAAAAAAAAAAAAAAAA=="); err == nil {
		t.Fatal("expected short public key error")
	}
	if _, err := PublicKeyFromWGPrivate("not base64!!"); err == nil {
		t.Fatal("expected invalid private key error")
	}
}

func TestGenerateAndParseAgeIdentity(t *testing.T) {
	identity, recipient, err := GenerateAgeIdentity()
	if err != nil {
		t.Fatalf("GenerateAgeIdentity: %v", err)
	}
	if !strings.HasPrefix(identity, "AGE-SECRET-KEY-1") {
		t.Fatalf("identity has unexpected prefix: %s", identity)
	}
	if !strings.HasPrefix(recipient, "age1") {
		t.Fatalf("recipient has unexpected prefix: %s", recipient)
	}
	parsed, err := ParseAgeIdentity(identity)
	if err != nil {
		t.Fatalf("ParseAgeIdentity: %v", err)
	}
	if got := parsed.Recipient().String(); got != recipient {
		t.Fatalf("recipient mismatch: got %s want %s", got, recipient)
	}
	if _, err := ParseAgeIdentity("AGE-SECRET-KEY-1NOPE"); err == nil {
		t.Fatal("expected bad identity error")
	}
}

func TestGenerateAndValidateEd25519Pair(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	pk, err := DecodeEd25519Public(pub)
	if err != nil {
		t.Fatalf("DecodeEd25519Public: %v", err)
	}
	if len(pk) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d", len(pk))
	}
	sk, err := DecodeEd25519Private(priv)
	if err != nil {
		t.Fatalf("DecodeEd25519Private: %v", err)
	}
	if len(sk) != ed25519.PrivateKeySize {
		t.Fatalf("private key length = %d", len(sk))
	}
	if err := ValidateEd25519Pair(pub, priv); err != nil {
		t.Fatalf("ValidateEd25519Pair: %v", err)
	}

	msg := []byte("tincan keys test message")
	sig := ed25519.Sign(sk, msg)
	if !ed25519.Verify(pk, msg, sig) {
		t.Fatal("signature did not verify")
	}
	if ed25519.Verify(pk, []byte("tincan keys test message!"), sig) {
		t.Fatal("signature verified for tampered message")
	}

	wrongPub, _, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEd25519Pair(wrongPub, priv); err == nil {
		t.Fatal("expected keypair mismatch error")
	}
}

func TestEd25519RejectsBadInputs(t *testing.T) {
	if _, err := DecodeEd25519Private("not base64!"); err == nil {
		t.Fatal("expected private key decode error")
	}
	if _, err := DecodeEd25519Private("AAAAAAAAAAAAAAAAAAAAAA=="); err == nil {
		t.Fatal("expected private key length error")
	}
	if _, err := DecodeEd25519Public("not base64!"); err == nil {
		t.Fatal("expected public key decode error")
	}
	if _, err := DecodeEd25519Public("AAAAAAAAAAAAAAAAAAAAAA=="); err == nil {
		t.Fatal("expected public key length error")
	}
}
