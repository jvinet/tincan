// Package nostr implements the slice of the Nostr protocol (NIP-01 events,
// NIP-19 key encodings, and a minimal relay client) that the nostr dead-drop
// backend needs. It deliberately depends on neither tincan's config nor drop
// packages: the protocol logic can then be unit-tested against known vectors
// with no network, and config can import it for key validation without a cycle.
package nostr

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Event is a NIP-01 event. The struct tags are the relay wire form; the id is a
// hash over a separate canonical serialization (see Serialize), not over this
// JSON.
type Event struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// Serialize returns the exact byte string whose sha256 is the event id, per
// NIP-01: the compact JSON array
//
//	[0, pubkey, created_at, kind, tags, content]
//
// with no insignificant whitespace and a specific string-escape set.
//
// This is hand-rolled rather than delegated to encoding/json on purpose.
// encoding/json escapes 0x08/0x0c as / (NIP-01 wants \b/\f) and,
// unless disabled, HTML-escapes < > & (NIP-01 wants them literal). Diverging by
// even one byte yields a different id than every other Nostr implementation, so
// relays would reject the event as having an invalid id even though it would
// round-trip locally. The known-vector test guards this.
func (e Event) Serialize() []byte {
	var b bytes.Buffer
	b.WriteString(`[0,"`)
	b.WriteString(e.PubKey)
	b.WriteString(`",`)
	b.WriteString(strconv.FormatInt(e.CreatedAt, 10))
	b.WriteByte(',')
	b.WriteString(strconv.Itoa(e.Kind))
	b.WriteByte(',')
	b.WriteByte('[')
	for i, tag := range e.Tags {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('[')
		for j, v := range tag {
			if j > 0 {
				b.WriteByte(',')
			}
			writeJSONString(&b, v)
		}
		b.WriteByte(']')
	}
	b.WriteByte(']')
	b.WriteByte(',')
	writeJSONString(&b, e.Content)
	b.WriteByte(']')
	return b.Bytes()
}

// writeJSONString writes s as a JSON string literal using NIP-01's escape rules.
// Bytes >= 0x20 (including all continuation bytes of multi-byte UTF-8 runes) are
// written verbatim, preserving the original UTF-8.
func writeJSONString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if c < 0x20 {
				fmt.Fprintf(b, `\u%04x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}

func (e Event) idBytes() [32]byte {
	return sha256.Sum256(e.Serialize())
}

// ComputeID returns the hex-encoded sha256 of the canonical serialization.
func (e Event) ComputeID() string {
	sum := e.idBytes()
	return hex.EncodeToString(sum[:])
}

// Verify checks that the event's id matches its serialization and that the
// schnorr signature is valid for that id under the event's own pubkey. It does
// NOT check the kind, tags, or which author is expected — the drop layer pins
// those, because a relay is free to return events that match none of them.
func (e Event) Verify() error {
	idBytes, err := hex.DecodeString(e.ID)
	if err != nil || len(idBytes) != 32 {
		return fmt.Errorf("event id is not 32-byte hex")
	}
	sum := e.idBytes()
	if !bytes.Equal(idBytes, sum[:]) {
		return fmt.Errorf("event id does not match its contents")
	}
	pkBytes, err := hex.DecodeString(e.PubKey)
	if err != nil || len(pkBytes) != 32 {
		return fmt.Errorf("event pubkey is not 32-byte hex")
	}
	pk, err := schnorr.ParsePubKey(pkBytes)
	if err != nil {
		return fmt.Errorf("parse event pubkey: %w", err)
	}
	sigBytes, err := hex.DecodeString(e.Sig)
	if err != nil || len(sigBytes) != 64 {
		return fmt.Errorf("event sig is not 64-byte hex")
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parse event sig: %w", err)
	}
	if !sig.Verify(sum[:], pk) {
		return fmt.Errorf("event signature verification failed")
	}
	return nil
}

// DTag returns the value of the first ["d", value] tag, or "" if there is none.
// The d tag is the NIP-33 identifier that, with the pubkey and kind, names a
// parameterized-replaceable event's slot.
func (e Event) DTag() string {
	for _, tag := range e.Tags {
		if len(tag) >= 2 && tag[0] == "d" {
			return tag[1]
		}
	}
	return ""
}
