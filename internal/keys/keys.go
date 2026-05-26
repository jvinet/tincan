package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func GenerateWGKeypair() (privateKey string, publicKey string, err error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	return priv.String(), priv.PublicKey().String(), nil
}

func PublicKeyFromWGPrivate(privateKey string) (string, error) {
	priv, err := wgtypes.ParseKey(strings.TrimSpace(privateKey))
	if err != nil {
		return "", fmt.Errorf("parse WireGuard private key: %w", err)
	}
	return priv.PublicKey().String(), nil
}

func ParseWGPublic(key string) (wgtypes.Key, error) {
	parsed, err := wgtypes.ParseKey(strings.TrimSpace(key))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("parse WireGuard public key: %w", err)
	}
	return parsed, nil
}

func ParseWGPrivate(key string) (wgtypes.Key, error) {
	parsed, err := wgtypes.ParseKey(strings.TrimSpace(key))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("parse WireGuard private key: %w", err)
	}
	return parsed, nil
}

func GenerateAgeIdentity() (identity string, recipient string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return id.String(), id.Recipient().String(), nil
}

func ParseAgeIdentity(identity string) (*age.X25519Identity, error) {
	id, err := age.ParseX25519Identity(strings.TrimSpace(identity))
	if err != nil {
		return nil, fmt.Errorf("parse age identity: %w", err)
	}
	return id, nil
}

func GenerateEd25519Keypair() (publicKey string, privateKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

func DecodeEd25519Public(key string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil {
		return nil, fmt.Errorf("decode ed25519 public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key has %d bytes, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

func DecodeEd25519Private(key string) (ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil {
		return nil, fmt.Errorf("decode ed25519 private key: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key has %d bytes, want %d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

func ValidateEd25519Pair(publicKey, privateKey string) error {
	pub, err := DecodeEd25519Public(publicKey)
	if err != nil {
		return err
	}
	priv, err := DecodeEd25519Private(privateKey)
	if err != nil {
		return err
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		return errors.New("ed25519 publisher private key does not match public key")
	}
	return nil
}
