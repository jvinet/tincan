package nostr

import (
	"strings"
	"testing"
)

// nip19PubHex is the public key from the canonical NIP-19 worked example; reused
// across tests as a realistic 32-byte hex pubkey.
const nip19PubHex = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"

// TestSerializeCanonical pins the exact bytes the id is hashed over. This is the
// interop gate: id = sha256(Serialize()), and sha256 is standard, so if these
// bytes are the canonical NIP-01 form then our id matches every other Nostr
// implementation. A regression in the escape rules shows up here, not as a
// mysterious "invalid id" rejection from a relay.
func TestSerializeCanonical(t *testing.T) {
	tests := []struct {
		name string
		ev   Event
		want string
	}{
		{
			name: "simple replaceable event",
			ev: Event{
				PubKey:    nip19PubHex,
				CreatedAt: 1700000000,
				Kind:      30078,
				Tags:      [][]string{{"d", "_tincan"}},
				Content:   "hello",
			},
			want: `[0,"` + nip19PubHex + `",1700000000,30078,[["d","_tincan"]],"hello"]`,
		},
		{
			name: "empty tags and content",
			ev: Event{
				PubKey:    nip19PubHex,
				CreatedAt: 1,
				Kind:      1,
				Tags:      [][]string{},
				Content:   "",
			},
			want: `[0,"` + nip19PubHex + `",1,1,[],""]`,
		},
		{
			// Every escape NIP-01 mandates, plus characters encoding/json would
			// mishandle: it emits / for \b/\f and (by default)
			// </>/& for < > &. NIP-01 wants \b \f and literal < > &.
			name: "escaping",
			ev: Event{
				PubKey:    nip19PubHex,
				CreatedAt: 42,
				Kind:      1,
				Tags:      [][]string{{"e", "id\"with\\stuff"}},
				Content:   "q:\" b:\\ nl:\n tab:\t bs:\b ff:\f cr:\r lt:< gt:> amp:& ctl:\x01 uni:é",
			},
			want: `[0,"` + nip19PubHex + `",42,1,[["e","id\"with\\stuff"]],"q:\" b:\\ nl:\n tab:\t bs:\b ff:\f cr:\r lt:< gt:> amp:& ctl:\u0001 uni:é"]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.ev.Serialize()); got != tt.want {
				t.Errorf("Serialize() mismatch\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	sk, err := ParseSecretKey(nip19NsecBech32)
	if err != nil {
		t.Fatalf("ParseSecretKey: %v", err)
	}
	ev := Event{
		CreatedAt: 1700000000,
		Kind:      30078,
		Tags:      [][]string{{"d", "_tincan"}},
		Content:   "directory blob goes here",
	}
	if err := SignEvent(&ev, sk); err != nil {
		t.Fatalf("SignEvent: %v", err)
	}
	if ev.PubKey != nip19PubHex {
		t.Errorf("signed event pubkey = %s, want %s", ev.PubKey, nip19PubHex)
	}
	if ev.ID != ev.ComputeID() {
		t.Errorf("ID field %s does not match ComputeID %s", ev.ID, ev.ComputeID())
	}
	if err := ev.Verify(); err != nil {
		t.Errorf("Verify of freshly signed event: %v", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	sk, err := ParseSecretKey(nip19NsecBech32)
	if err != nil {
		t.Fatalf("ParseSecretKey: %v", err)
	}
	base := Event{CreatedAt: 100, Kind: 30078, Tags: [][]string{{"d", "_tincan"}}, Content: "payload"}
	if err := SignEvent(&base, sk); err != nil {
		t.Fatalf("SignEvent: %v", err)
	}
	if err := base.Verify(); err != nil {
		t.Fatalf("control: signed event should verify: %v", err)
	}

	t.Run("mutated content keeps old id", func(t *testing.T) {
		bad := base
		bad.Content = "tampered" // id no longer matches the serialization
		if err := bad.Verify(); err == nil {
			t.Error("expected verify failure after content change")
		}
	})
	t.Run("mutated created_at keeps old id", func(t *testing.T) {
		bad := base
		bad.CreatedAt = 101
		if err := bad.Verify(); err == nil {
			t.Error("expected verify failure after created_at change")
		}
	})
	t.Run("flipped signature byte", func(t *testing.T) {
		bad := base
		// Flip the last hex nibble of the signature.
		flip := map[byte]byte{'0': '1', '1': '0'}
		last := bad.Sig[len(bad.Sig)-1]
		repl, ok := flip[last]
		if !ok {
			repl = '0'
			if last == '0' {
				repl = '1'
			}
		}
		bad.Sig = bad.Sig[:len(bad.Sig)-1] + string(repl)
		if err := bad.Verify(); err == nil {
			t.Error("expected verify failure after signature change")
		}
	})
	t.Run("different author pubkey", func(t *testing.T) {
		bad := base
		bad.PubKey = strings.Repeat("a", 64) // valid hex length, wrong (and off-curve) key
		if err := bad.Verify(); err == nil {
			t.Error("expected verify failure after pubkey change")
		}
	})
}

func TestDTag(t *testing.T) {
	tests := []struct {
		tags [][]string
		want string
	}{
		{[][]string{{"d", "_tincan"}}, "_tincan"},
		{[][]string{{"e", "x"}, {"d", "net2"}}, "net2"},
		{[][]string{{"d"}}, ""},                                // malformed d tag (no value)
		{[][]string{{"e", "x"}}, ""},                           // no d tag
		{nil, ""},                                              // no tags
		{[][]string{{"d", "first"}, {"d", "second"}}, "first"}, // first wins
	}
	for _, tt := range tests {
		if got := (Event{Tags: tt.tags}).DTag(); got != tt.want {
			t.Errorf("DTag(%v) = %q, want %q", tt.tags, got, tt.want)
		}
	}
}
