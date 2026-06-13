package drop

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/nostr"
)

// fakeRelay is an in-memory nostr.Conn. It plays the role the lookupFunc plays
// for the dns drop: tests drive the drop with no network.
type fakeRelay struct {
	events    []nostr.Event // returned by Query
	queryErr  error         // if set, Query fails
	rejectPub bool          // if true, Publish returns a RelayError (OK,false)
	pubErr    error         // if set, Publish fails at the transport
	published []nostr.Event // events accepted by Publish
}

func (f *fakeRelay) Publish(_ context.Context, e nostr.Event) error {
	if f.pubErr != nil {
		return f.pubErr
	}
	if f.rejectPub {
		return &nostr.RelayError{Reason: "blocked: test relay rejects"}
	}
	f.published = append(f.published, e)
	f.events = append(f.events, e) // a later Query observes it
	return nil
}

func (f *fakeRelay) Query(_ context.Context, _ nostr.Filter) ([]nostr.Event, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return f.events, nil
}

func (f *fakeRelay) Close() error { return nil }

func fakeDialer(relays map[string]*fakeRelay) nostr.Dialer {
	return func(_ context.Context, relayURL string) (nostr.Conn, error) {
		r, ok := relays[relayURL]
		if !ok {
			return nil, errors.New("no such relay: " + relayURL)
		}
		return r, nil
	}
}

// newNostrDrop builds a drop wired to fake relays. relays keys must be already
// normalized (lowercase, no trailing slash) since the drop compares against the
// normalized form.
func newNostrDrop(sk *btcec.PrivateKey, author string, relays map[string]*fakeRelay) *Nostr {
	urls := make([]string, 0, len(relays))
	for u := range relays {
		urls = append(urls, u)
	}
	return &Nostr{
		relays:     urls,
		author:     author,
		identifier: nostrDefaultIdentifier,
		sk:         sk,
		dial:       fakeDialer(relays),
		name:       "nostr:test",
	}
}

func testKey(t *testing.T) (*btcec.PrivateKey, string) {
	t.Helper()
	nsec, _, err := nostr.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sk, err := nostr.ParseSecretKey(nsec)
	if err != nil {
		t.Fatalf("ParseSecretKey: %v", err)
	}
	return sk, nostr.PublicKeyHex(sk)
}

// signEv builds a signed event with the given fields. content is taken verbatim,
// so callers pass base64 for genuine directory events.
func signEv(t *testing.T, sk *btcec.PrivateKey, kind int, dtag, content string, createdAt int64) nostr.Event {
	t.Helper()
	ev := nostr.Event{CreatedAt: createdAt, Kind: kind, Tags: [][]string{{"d", dtag}}, Content: content}
	if err := nostr.SignEvent(&ev, sk); err != nil {
		t.Fatalf("SignEvent: %v", err)
	}
	return ev
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestNostrPutGetRoundTrip(t *testing.T) {
	sk, author := testKey(t)
	relay := &fakeRelay{}
	d := newNostrDrop(sk, author, map[string]*fakeRelay{"wss://relay.example": relay})

	blob := []byte("sealed directory blob")
	if err := d.Put(context.Background(), blob); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if len(relay.published) != 1 {
		t.Fatalf("expected 1 published event, got %d", len(relay.published))
	}
	pub := relay.published[0]
	if pub.Kind != nostrKind {
		t.Errorf("published kind = %d, want %d", pub.Kind, nostrKind)
	}
	if pub.DTag() != nostrDefaultIdentifier {
		t.Errorf("published d-tag = %q, want %q", pub.DTag(), nostrDefaultIdentifier)
	}
	if err := pub.Verify(); err != nil {
		t.Errorf("published event does not verify: %v", err)
	}

	got, err := d.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(blob) {
		t.Errorf("round-trip mismatch: got %q want %q", got, blob)
	}
}

func TestNostrMultiRelayNewestWins(t *testing.T) {
	sk, author := testKey(t)
	old := signEv(t, sk, nostrKind, nostrDefaultIdentifier, b64([]byte("old")), 100)
	mid := signEv(t, sk, nostrKind, nostrDefaultIdentifier, b64([]byte("mid")), 200)
	newest := signEv(t, sk, nostrKind, nostrDefaultIdentifier, b64([]byte("newest")), 300)

	relays := map[string]*fakeRelay{
		"wss://a.example": {events: []nostr.Event{old}},
		"wss://b.example": {events: []nostr.Event{mid}},
		"wss://c.example": {events: []nostr.Event{newest}}, // newest lives only here
	}
	d := newNostrDrop(nil, author, relays)
	got, err := d.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "newest" {
		t.Errorf("got %q, want newest", got)
	}
}

func TestNostrIgnoresInvalidEvents(t *testing.T) {
	sk, author := testKey(t)
	otherSK, _ := testKey(t)

	genuine := signEv(t, sk, nostrKind, nostrDefaultIdentifier, b64([]byte("real directory")), 500)

	wrongAuthor := signEv(t, otherSK, nostrKind, nostrDefaultIdentifier, b64([]byte("imposter")), 900)
	wrongKind := signEv(t, sk, 1, nostrDefaultIdentifier, b64([]byte("note")), 900)
	wrongDTag := signEv(t, sk, nostrKind, "other-network", b64([]byte("other net")), 900)

	badSig := signEv(t, sk, nostrKind, nostrDefaultIdentifier, b64([]byte("tampered sig")), 900)
	badSig.Sig = flipLastHex(badSig.Sig)

	badID := signEv(t, sk, nostrKind, nostrDefaultIdentifier, b64([]byte("orig")), 900)
	badID.Content = b64([]byte("swapped after signing")) // id no longer matches

	relay := &fakeRelay{events: []nostr.Event{wrongAuthor, wrongKind, wrongDTag, badSig, badID, genuine}}
	d := newNostrDrop(nil, author, map[string]*fakeRelay{"wss://r.example": relay})

	got, err := d.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "real directory" {
		t.Errorf("got %q, want the genuine directory despite higher-timestamp junk", got)
	}

	// With only junk present, the slot reads as empty.
	junkOnly := &fakeRelay{events: []nostr.Event{wrongAuthor, wrongKind, wrongDTag, badSig, badID}}
	d2 := newNostrDrop(nil, author, map[string]*fakeRelay{"wss://r.example": junkOnly})
	if _, err := d2.Get(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("junk-only Get error = %v, want ErrNotFound", err)
	}
}

func TestNostrPutReadOnlyWithoutNsec(t *testing.T) {
	_, author := testKey(t)
	d := newNostrDrop(nil, author, map[string]*fakeRelay{"wss://r.example": {}})
	if err := d.Put(context.Background(), []byte("x")); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Put without nsec error = %v, want ErrReadOnly", err)
	}
}

func TestNostrGetEmptySlot(t *testing.T) {
	_, author := testKey(t)
	d := newNostrDrop(nil, author, map[string]*fakeRelay{"wss://r.example": {}})
	if _, err := d.Get(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty-slot Get error = %v, want ErrNotFound", err)
	}
}

func TestNostrAllRelaysDownIsNotNotFound(t *testing.T) {
	_, author := testKey(t)
	down := errors.New("connection refused")
	relays := map[string]*fakeRelay{
		"wss://a.example": {queryErr: down},
		"wss://b.example": {queryErr: down},
	}
	d := newNostrDrop(nil, author, relays)
	_, err := d.Get(context.Background())
	if err == nil {
		t.Fatal("expected an error when all relays fail")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("all-relays-down must not be reported as ErrNotFound (sync would discard the cache)")
	}
}

func TestNostrGetOversizedRejected(t *testing.T) {
	sk, author := testKey(t)
	big := make([]byte, directory.MaxBlobSize+1)
	ev := signEv(t, sk, nostrKind, nostrDefaultIdentifier, b64(big), 100)
	d := newNostrDrop(nil, author, map[string]*fakeRelay{"wss://r.example": {events: []nostr.Event{ev}}})
	if _, err := d.Get(context.Background()); err == nil {
		t.Error("expected error for oversized event content")
	}
}

func TestNostrPutOversizedRejected(t *testing.T) {
	sk, author := testKey(t)
	d := newNostrDrop(sk, author, map[string]*fakeRelay{"wss://r.example": {}})
	if err := d.Put(context.Background(), make([]byte, directory.MaxBlobSize+1)); err == nil {
		t.Error("expected error publishing an oversized blob")
	}
}

func TestNostrPutPartialFailure(t *testing.T) {
	sk, author := testKey(t)
	relays := map[string]*fakeRelay{
		"wss://ok.example":   {},
		"wss://bad1.example": {rejectPub: true},
		"wss://bad2.example": {rejectPub: true},
	}
	d := newNostrDrop(sk, author, relays)
	if err := d.Put(context.Background(), []byte("blob")); err != nil {
		t.Errorf("Put should succeed when at least one relay accepts, got %v", err)
	}
	if len(relays["wss://ok.example"].published) != 1 {
		t.Error("the accepting relay should hold the event")
	}

	// When every relay rejects, Put fails.
	allBad := map[string]*fakeRelay{
		"wss://bad1.example": {rejectPub: true},
		"wss://bad2.example": {rejectPub: true},
	}
	d2 := newNostrDrop(sk, author, allBad)
	if err := d2.Put(context.Background(), []byte("blob")); err == nil {
		t.Error("Put should fail when no relay accepts")
	}
}

func TestNewNostrPairing(t *testing.T) {
	nsec, npub, err := nostr.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	author, err := nostr.ParsePublicKey(npub)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	relays := []string{"wss://relay.example"}

	// A different nsec does not match the pinned author.
	otherNsec, _, _ := nostr.GenerateKey()
	if _, err := NewNostr(relays, author, otherNsec, ""); err == nil {
		t.Error("expected error when nsec does not match author")
	}

	// The matching pair is accepted, and the drop is read-write.
	d, err := NewNostr(relays, author, nsec, "")
	if err != nil {
		t.Fatalf("NewNostr with matching pair: %v", err)
	}
	if d.sk == nil {
		t.Error("expected a writable drop when a matching nsec is supplied")
	}
}

func TestNewNostrNormalizesAndDedupes(t *testing.T) {
	_, author := testKey(t)
	d, err := NewNostr([]string{
		"wss://Relay.Example/",
		"wss://relay.example", // same as above after normalization
		"wss://other.example",
	}, author, "", "")
	if err != nil {
		t.Fatalf("NewNostr: %v", err)
	}
	if len(d.relays) != 2 {
		t.Errorf("expected 2 relays after dedup, got %d: %v", len(d.relays), d.relays)
	}

	if _, err := NewNostr([]string{"http://relay.example"}, author, "", ""); err == nil {
		t.Error("expected rejection of a non-ws relay scheme")
	}
	if _, err := NewNostr(nil, author, "", ""); err == nil {
		t.Error("expected rejection of an empty relay list")
	}
}

func flipLastHex(s string) string {
	if s == "" {
		return s
	}
	last := s[len(s)-1]
	repl := byte('0')
	if last == '0' {
		repl = '1'
	}
	return s[:len(s)-1] + string(repl)
}
