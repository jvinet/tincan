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
	// for this peer. Informational; the blacklist is keyed on FailedEndpoint.
	FailedAt time.Time `json:"failed_at,omitzero"`
	// FailedEndpoint is the Endpoint value that was marked failed. While it
	// equals Endpoint the entry is blacklisted: a beacon repeating that same
	// address does not resurrect it (a beacon is unauthenticated, so a
	// spoofed flood otherwise re-validates a dead path indefinitely — see
	// spec/lan-discovery.md § Security considerations). Only a beacon
	// advertising a *different* endpoint clears the failure, since that is a
	// genuinely new candidate worth a probe.
	FailedEndpoint string `json:"failed_endpoint,omitempty"`
}

// Blacklisted reports whether the current Endpoint is the one that was marked
// failed and not yet superseded by a different candidate.
func (s LANState) Blacklisted() bool {
	return s.Endpoint != "" && s.FailedEndpoint == s.Endpoint
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
	if s.Blacklisted() {
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

// Update inserts or refreshes a peer entry. Beacons are unauthenticated, so
// Update is deliberately conservative about *changing* a known endpoint:
//
//   - First beacon for a pubkey: learn it.
//   - Same endpoint as stored: refresh liveness only. A repeat never clears a
//     failure for that same endpoint — otherwise a spoofed beacon flood could
//     keep resurrecting a dead path.
//   - Different endpoint while the current one is still usable: reject (pin).
//     An unsolicited beacon cannot displace a working/valid endpoint; the
//     incumbent must fail (MarkFailed) or age out (TTL) first. This bounds a
//     LAN attacker to the same ~90s blast radius a single spoofed beacon
//     already has, instead of letting a flood hold a peer hostage.
//   - Different endpoint while the current one is stale or failed: accept it
//     as a fresh candidate and clear the failure.
//
// Same-NAT peers are unaffected by the blacklist: chooseEndpoint looks them
// up with staleOK, bypassing Usable entirely, so their recovery path is
// unchanged.
func (s *Store) Update(pubkey, endpoint string, now time.Time) UpdateResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, hadPrev := s.entries[pubkey]
	if !hadPrev {
		s.entries[pubkey] = LANState{Endpoint: endpoint, LearnedAt: now}
		return UpdateResult{Changed: true, FirstSeen: true}
	}
	if endpoint == prev.Endpoint {
		// Refresh liveness; preserve any failure on this same endpoint.
		next := prev
		next.LearnedAt = now
		s.entries[pubkey] = next
		return UpdateResult{}
	}
	if prev.Usable(now, s.ttl) {
		return UpdateResult{} // pinned: don't let an unsolicited beacon move it
	}
	// Incumbent is stale or failed — the new endpoint is a fresh candidate.
	s.entries[pubkey] = LANState{Endpoint: endpoint, LearnedAt: now}
	return UpdateResult{Changed: true}
}

// MarkFailed records that the peer's current LAN endpoint just failed (the
// relay state machine observed a DIRECT→RELAYED transition). That specific
// endpoint stays blacklisted until a beacon advertises a different one.
func (s *Store) MarkFailed(pubkey string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[pubkey]
	if !ok {
		return
	}
	entry.FailedAt = now
	entry.FailedEndpoint = entry.Endpoint
	s.entries[pubkey] = entry
}

// GC removes entries not refreshed within maxAge and entries whose pubkey is
// no longer a directory member. The listener already gates inserts on
// membership, so a removed node's beacons are dropped and its entry simply
// ages out; this also reclaims it immediately once the directory drops it.
// Returns the number of entries removed.
func (s *Store) GC(now time.Time, maxAge time.Duration, members map[string]bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for pubkey, entry := range s.entries {
		stale := !entry.LearnedAt.IsZero() && now.Sub(entry.LearnedAt) > maxAge
		gone := members != nil && !members[pubkey]
		if stale || gone {
			delete(s.entries, pubkey)
			removed++
		}
	}
	return removed
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
