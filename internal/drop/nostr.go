package drop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/nostr"
)

const (
	// nostrKind is the NIP-78 "application-specific data" kind. Relays keep only
	// the latest event per (pubkey, kind, d-tag), which is exactly the single
	// mutable slot a dead drop needs. Fixed, like the dns drop's "tc1" prefix.
	nostrKind = 30078
	// nostrDefaultIdentifier is the default ["d", …] tag value; it namespaces the
	// slot so one key can host multiple networks.
	nostrDefaultIdentifier = "_tincan"
	// nostrRelayTimeout bounds a single relay round-trip when the caller's
	// context carries no deadline, so one dead relay never stalls the fan-out.
	nostrRelayTimeout = 30 * time.Second
)

// Nostr is a dead-drop backed by a NIP-78 replaceable event on one or more Nostr
// relays. Reads need only the admin's public key and the relay list (no secret),
// so any node can sync; writes need the admin's secret key (nsec) and are used
// only by the admin. Without a secret the drop is read-only, like the http and
// dns backends.
//
// Relays are untrusted: one may withhold the event, serve a stale copy, or
// return unrelated or forged events. Get therefore verifies every event (author,
// kind, d-tag, id, schnorr signature) and selects the newest survivor, mirroring
// how the dns drop ignores foreign TXT records. Authenticity of the directory
// itself does not rest on the relay or even the Nostr key: the blob is
// independently age-encrypted and ed25519-signed by the directory layer, and
// rollback is caught by the directory's monotonic serial. The Nostr signature
// only controls who may write the relay slot.
type Nostr struct {
	relays     []string
	author     string            // canonical x-only pubkey hex; events must match
	identifier string            // the d-tag value
	sk         *btcec.PrivateKey // nil => read-only
	dial       nostr.Dialer      // DefaultDialer in prod; a fake in tests
	name       string
}

// NewNostr builds a Nostr drop. author is the admin's public key (npub or hex);
// nsec is the admin's secret key (empty on read-only nodes); identifier is the
// d-tag (empty defaults to "_tincan"). It takes plain scalars rather than a
// config.DropBackend so the nostr package and config package need not depend on
// each other — mirroring NewHTTP(url, user, pass).
func NewNostr(relays []string, author, nsec, identifier string) (*Nostr, error) {
	authorHex, err := nostr.ParsePublicKey(author)
	if err != nil {
		return nil, fmt.Errorf("nostr drop author: %w", err)
	}
	norm, err := normalizeRelays(relays)
	if err != nil {
		return nil, err
	}
	if len(norm) == 0 {
		return nil, errors.New("nostr drop requires at least one relay")
	}
	if identifier == "" {
		identifier = nostrDefaultIdentifier
	}
	n := &Nostr{
		relays:     norm,
		author:     authorHex,
		identifier: identifier,
		dial:       nostr.DefaultDialer,
		name:       fmt.Sprintf("nostr:%s (%d relays)", authorHex[:8], len(norm)),
	}
	if nsec != "" {
		sk, err := nostr.ParseSecretKey(nsec)
		if err != nil {
			return nil, fmt.Errorf("nostr drop nsec: %w", err)
		}
		// Fail fast if the secret does not match the pinned author. A drop can be
		// built straight from a bootstrap, so this guards more than config does.
		if got := nostr.PublicKeyHex(sk); got != authorHex {
			return nil, errors.New("nostr drop nsec does not match author public key")
		}
		n.sk = sk
	}
	return n, nil
}

// normalizeRelays canonicalizes and de-duplicates relay URLs so duplicates do
// not waste connections or double-count publish acks.
func normalizeRelays(relays []string) ([]string, error) {
	seen := make(map[string]bool, len(relays))
	out := make([]string, 0, len(relays))
	for _, r := range relays {
		norm, err := nostr.NormalizeRelayURL(r)
		if err != nil {
			return nil, err
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	return out, nil
}

func (n *Nostr) Name() string { return n.name }

func (n *Nostr) Get(ctx context.Context) ([]byte, error) {
	filter := nostr.Filter{
		Authors: []string{n.author},
		Kinds:   []int{nostrKind},
		DTags:   []string{n.identifier},
		Limit:   1,
	}
	type queryResult struct {
		events []nostr.Event
		err    error
	}
	results := make(chan queryResult, len(n.relays))
	for _, relayURL := range n.relays {
		go func(relayURL string) {
			rctx, cancel := relayContext(ctx)
			defer cancel()
			events, err := n.queryRelay(rctx, relayURL, filter)
			results <- queryResult{events: events, err: err}
		}(relayURL)
	}

	var (
		best    nostr.Event
		haveOne bool
		clean   int // relays that returned without error
		errs    []error
	)
	for range n.relays {
		r := <-results
		if r.err != nil {
			errs = append(errs, r.err)
		} else {
			clean++
		}
		for _, ev := range r.events {
			if !n.validEvent(&ev) {
				continue
			}
			// Newest wins; ties break on lowest id (NIP-01) so every client
			// deterministically selects the same event.
			if !haveOne || ev.CreatedAt > best.CreatedAt ||
				(ev.CreatedAt == best.CreatedAt && ev.ID < best.ID) {
				best, haveOne = ev, true
			}
		}
	}

	if !haveOne {
		// Distinguish an empty slot (ErrNotFound, so the caller treats it as "no
		// directory yet") from every relay failing (a transport error, so sync
		// keeps the cached directory rather than discarding it). If at least one
		// relay answered cleanly with nothing, the slot is genuinely empty.
		if clean == 0 && len(errs) > 0 {
			return nil, fmt.Errorf("nostr drop: all relays failed: %w", errors.Join(errs...))
		}
		return nil, ErrNotFound
	}

	blob, err := base64.StdEncoding.DecodeString(best.Content)
	if err != nil {
		return nil, fmt.Errorf("nostr drop: decode event content: %w", err)
	}
	if int64(len(blob)) > directory.MaxBlobSize {
		return nil, fmt.Errorf("nostr drop: directory blob is %d bytes (max %d)", len(blob), directory.MaxBlobSize)
	}
	return blob, nil
}

func (n *Nostr) Put(ctx context.Context, data []byte) error {
	if n.sk == nil {
		return fmt.Errorf("nostr drop has no nsec configured: %w", ErrReadOnly)
	}
	if int64(len(data)) > directory.MaxBlobSize {
		return fmt.Errorf("nostr drop: directory blob is %d bytes (max %d)", len(data), directory.MaxBlobSize)
	}
	ev := nostr.Event{
		CreatedAt: time.Now().Unix(),
		Kind:      nostrKind,
		Tags:      [][]string{{"d", n.identifier}},
		Content:   base64.StdEncoding.EncodeToString(data),
	}
	if err := nostr.SignEvent(&ev, n.sk); err != nil {
		return fmt.Errorf("nostr drop: sign event: %w", err)
	}

	type pubResult struct {
		relay string
		err   error
	}
	results := make(chan pubResult, len(n.relays))
	for _, relayURL := range n.relays {
		go func(relayURL string) {
			rctx, cancel := relayContext(ctx)
			defer cancel()
			results <- pubResult{relay: relayURL, err: n.publishToRelay(rctx, relayURL, ev)}
		}(relayURL)
	}

	var (
		accepted int
		errs     []error
	)
	for range n.relays {
		r := <-results
		if r.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.relay, r.err))
		} else {
			accepted++
		}
	}
	// A dead drop is durable as long as one relay holds the event; readers merge
	// across all of them. Surface every rejection (size, auth, rate-limit) when
	// none accepted so the admin can see why.
	if accepted == 0 {
		return fmt.Errorf("nostr drop: no relay accepted the directory: %w", errors.Join(errs...))
	}
	return nil
}

func (n *Nostr) Stat(ctx context.Context) (Metadata, error) {
	blob, err := n.Get(ctx)
	if err != nil {
		return Metadata{}, err
	}
	// As with the dns drop, derive a stable ETag from the content; the event's
	// created_at is not a reliable mtime across relays, so leave UpdatedAt zero.
	sum := sha256.Sum256(blob)
	return Metadata{Size: int64(len(blob)), ETag: hex.EncodeToString(sum[:8])}, nil
}

// validEvent reports whether ev is a genuine directory event for this drop: it
// must come from the pinned author, carry our kind and d-tag, and have a valid
// id and schnorr signature. This is the analog of the dns drop ignoring foreign
// TXT records, and it is what makes the relay-side authors/#d filter untrusted
// but harmless.
func (n *Nostr) validEvent(ev *nostr.Event) bool {
	return ev.PubKey == n.author &&
		ev.Kind == nostrKind &&
		ev.DTag() == n.identifier &&
		ev.Verify() == nil
}

func (n *Nostr) queryRelay(ctx context.Context, relayURL string, f nostr.Filter) ([]nostr.Event, error) {
	conn, err := n.dial(ctx, relayURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.Query(ctx, f)
}

func (n *Nostr) publishToRelay(ctx context.Context, relayURL string, ev nostr.Event) error {
	conn, err := n.dial(ctx, relayURL)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Publish(ctx, ev)
}

// relayContext derives a per-relay context: it respects the caller's deadline
// when one is set, otherwise bounds the round-trip with nostrRelayTimeout.
func relayContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, nostrRelayTimeout)
}
