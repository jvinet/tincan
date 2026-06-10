package discovery

import (
	"maps"
	"sync"
	"time"
)

// LANState is a per-peer entry in the discovery store.
type LANState struct {
	// Endpoint is the candidate LAN address (host:port) learned from the
	// most recent beacon.
	Endpoint string `json:"endpoint,omitempty"`
	// LearnedAt is when the most recent beacon arrived.
	LearnedAt time.Time `json:"learned_at,omitzero"`
	// FailedAt is the most recent time we observed a DIRECT→RELAYED transition
	// for this peer. When FailedAt is newer than LearnedAt, the entry is
	// considered blacklisted until a fresh beacon arrives.
	FailedAt time.Time `json:"failed_at,omitzero"`
}

// Usable reports whether the entry can be presented as an endpoint candidate
// to WireGuard, given the current time and the configured TTL.
func (s LANState) Usable(now time.Time, ttl time.Duration) bool {
	if s.Endpoint == "" || s.LearnedAt.IsZero() {
		return false
	}
	if now.Sub(s.LearnedAt) > ttl {
		return false
	}
	if !s.FailedAt.IsZero() && !s.FailedAt.Before(s.LearnedAt) {
		return false
	}
	return true
}

// Store holds the per-peer LAN endpoint state. It also carries the local
// node's pubkey and current WireGuard listen port so the sender can fetch
// them without re-parsing config on each cycle.
type Store struct {
	ttl time.Duration

	mu       sync.RWMutex
	entries  map[string]LANState
	selfPub  string
	selfPort uint16
}

// NewStore returns an empty Store with the given LAN endpoint TTL.
func NewStore(ttl time.Duration) *Store {
	return &Store{ttl: ttl, entries: make(map[string]LANState)}
}

// TTL returns the configured staleness window for LAN endpoints.
func (s *Store) TTL() time.Duration { return s.ttl }

// SetSelf updates the local node's pubkey and listen port. Called by the
// daemon loop after each iteration so the sender can include up-to-date
// information in outbound beacons. Until selfPort > 0, the sender skips.
func (s *Store) SetSelf(pubkey string, port uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selfPub = pubkey
	s.selfPort = port
}

// Self returns the most recent (pubkey, port) tuple from SetSelf. The second
// return value is false until SetSelf has been called with a non-zero port.
func (s *Store) Self() (string, uint16, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.selfPub, s.selfPort, s.selfPort != 0 && s.selfPub != ""
}

// Lookup returns the usable LAN endpoint for pubkey, or "" if none is known
// or the entry is stale/blacklisted.
func (s *Store) Lookup(pubkey string, now time.Time) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[pubkey]
	if !ok {
		return ""
	}
	if !entry.Usable(now, s.ttl) {
		return ""
	}
	return entry.Endpoint
}

// LookupLastKnown returns the most recently learned LAN endpoint for
// pubkey regardless of TTL expiry or failure-blacklisting, or "" if no
// beacon was ever received from it. Callers use this when every
// alternative is known to be worse — a peer behind the same NAT as self,
// whose directory endpoint would require hairpin routing.
func (s *Store) LookupLastKnown(pubkey string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.entries[pubkey].Endpoint
}

// UpdateResult describes what changed after an Update call.
type UpdateResult struct {
	// Changed is true when the entry represents a meaningful state
	// transition (new pubkey, endpoint changed, or blacklist cleared).
	Changed bool
	// FirstSeen is true when the pubkey had no prior entry. Used to gate
	// reactive beacons: we only respond to brand-new peers, not refreshes.
	FirstSeen bool
}

// Update inserts or refreshes a peer entry.
func (s *Store) Update(pubkey, endpoint string, now time.Time) UpdateResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, hadPrev := s.entries[pubkey]
	next := LANState{
		Endpoint:  endpoint,
		LearnedAt: now,
		FailedAt:  prev.FailedAt,
	}
	s.entries[pubkey] = next
	if !hadPrev {
		return UpdateResult{Changed: true, FirstSeen: true}
	}
	if prev.Endpoint != endpoint {
		return UpdateResult{Changed: true}
	}
	if !prev.FailedAt.IsZero() && prev.FailedAt.After(prev.LearnedAt) {
		return UpdateResult{Changed: true}
	}
	return UpdateResult{}
}

// MarkFailed records that the peer's LAN endpoint just failed (the relay
// state machine observed a DIRECT→RELAYED transition). The entry stays
// blacklisted until the next beacon arrives.
func (s *Store) MarkFailed(pubkey string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[pubkey]
	if !ok {
		return
	}
	entry.FailedAt = now
	s.entries[pubkey] = entry
}

// Snapshot returns a copy of the current store contents. Safe for use by
// status displays and tests.
func (s *Store) Snapshot() map[string]LANState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]LANState, len(s.entries))
	maps.Copy(out, s.entries)
	return out
}
