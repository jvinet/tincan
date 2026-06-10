package discovery

import (
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

func TestStoreUpdateFirstSeen(t *testing.T) {
	s := NewStore(90 * time.Second)
	now := time.Now()
	r := s.Update("alice", "10.0.0.1:51820", now)
	if !r.Changed || !r.FirstSeen {
		t.Fatalf("first update should be Changed+FirstSeen, got %+v", r)
	}
	r = s.Update("alice", "10.0.0.1:51820", now.Add(30*time.Second))
	if r.Changed || r.FirstSeen {
		t.Fatalf("idempotent update should be neither, got %+v", r)
	}
	// A different endpoint is pinned out while the incumbent is still usable.
	r = s.Update("alice", "10.0.0.2:51820", now.Add(60*time.Second))
	if r.Changed || r.FirstSeen {
		t.Fatalf("endpoint-change while usable should be rejected, got %+v", r)
	}
	if got := s.Lookup("alice", now.Add(61*time.Second)); got != "10.0.0.1:51820" {
		t.Fatalf("pinned endpoint = %q, want the incumbent", got)
	}
	// Once the incumbent ages out, the next different endpoint is accepted.
	r = s.Update("alice", "10.0.0.2:51820", now.Add(200*time.Second))
	if !r.Changed || r.FirstSeen {
		t.Fatalf("endpoint-change after TTL should be Changed, got %+v", r)
	}
	if got := s.Lookup("alice", now.Add(200*time.Second)); got != "10.0.0.2:51820" {
		t.Fatalf("post-TTL endpoint = %q", got)
	}
}

// A spoofed beacon repeating the exact endpoint that just failed must not
// resurrect it; only a different candidate clears the failure.
func TestStoreFailedEndpointNotResurrectedBySameBeacon(t *testing.T) {
	s := NewStore(90 * time.Second)
	t0 := time.Now()
	s.Update("alice", "10.0.0.1:51820", t0)
	s.MarkFailed("alice", t0.Add(time.Second))
	if got := s.Lookup("alice", t0.Add(2*time.Second)); got != "" {
		t.Fatalf("blacklisted lookup = %q, want empty", got)
	}
	// Same endpoint, repeatedly — stays blacklisted no matter how fresh.
	for i := range 5 {
		s.Update("alice", "10.0.0.1:51820", t0.Add(time.Duration(10+i)*time.Second))
	}
	if got := s.Lookup("alice", t0.Add(20*time.Second)); got != "" {
		t.Fatalf("same-endpoint beacons resurrected a failed path: %q", got)
	}
	// A different endpoint is a fresh candidate and clears the failure.
	r := s.Update("alice", "10.0.0.9:51820", t0.Add(30*time.Second))
	if !r.Changed {
		t.Fatalf("different endpoint after failure should be Changed, got %+v", r)
	}
	if got := s.Lookup("alice", t0.Add(31*time.Second)); got != "10.0.0.9:51820" {
		t.Fatalf("recovered lookup = %q", got)
	}
}

func TestStoreGC(t *testing.T) {
	ttl := 90 * time.Second
	s := NewStore(ttl)
	t0 := time.Now()
	s.Update("alice", "10.0.0.1:51820", t0)
	s.Update("bob", "10.0.0.2:51820", t0)

	// alice is still a member and fresh; bob left the directory.
	if removed := s.GC(t0.Add(time.Minute), 10*ttl, map[string]bool{"alice": true}); removed != 1 {
		t.Fatalf("membership GC removed %d, want 1", removed)
	}
	if got := s.LookupLastKnown("bob"); got != "" {
		t.Fatal("bob entry survived membership GC")
	}
	if got := s.LookupLastKnown("alice"); got == "" {
		t.Fatal("alice entry wrongly GC'd")
	}
	// alice ages out past 10×TTL even while still a member.
	if removed := s.GC(t0.Add(11*ttl), 10*ttl, map[string]bool{"alice": true}); removed != 1 {
		t.Fatalf("staleness GC removed %d, want 1", removed)
	}
	if got := s.LookupLastKnown("alice"); got != "" {
		t.Fatal("stale alice entry survived GC")
	}
}

func TestStoreLookupTTL(t *testing.T) {
	s := NewStore(90 * time.Second)
	now := time.Now()
	s.Update("alice", "10.0.0.1:51820", now)
	if got := s.Lookup("alice", now); got != "10.0.0.1:51820" {
		t.Fatalf("fresh lookup = %q", got)
	}
	if got := s.Lookup("alice", now.Add(91*time.Second)); got != "" {
		t.Fatalf("stale lookup = %q, want empty", got)
	}
	if got := s.Lookup("unknown", now); got != "" {
		t.Fatalf("unknown lookup = %q, want empty", got)
	}
}

func TestStoreMarkFailedBlacklistsCurrentEndpoint(t *testing.T) {
	s := NewStore(90 * time.Second)
	t0 := time.Now()
	s.Update("alice", "10.0.0.1:51820", t0)
	if s.Lookup("alice", t0) == "" {
		t.Fatal("expected initial lookup to succeed")
	}
	s.MarkFailed("alice", t0.Add(time.Second))
	if got := s.Lookup("alice", t0.Add(2*time.Second)); got != "" {
		t.Fatalf("blacklisted lookup = %q, want empty", got)
	}
	// LookupLastKnown ignores the blacklist (same-NAT recovery path).
	if got := s.LookupLastKnown("alice"); got != "10.0.0.1:51820" {
		t.Fatalf("last-known while blacklisted = %q", got)
	}
}

func TestStoreLookupLastKnown(t *testing.T) {
	s := NewStore(90 * time.Second)
	now := time.Now()
	if got := s.LookupLastKnown("alice"); got != "" {
		t.Fatalf("never-seen peer = %q, want empty", got)
	}
	s.Update("alice", "10.0.0.1:51820", now)

	// Past TTL: strict Lookup refuses, last-known still serves.
	stale := now.Add(10 * time.Minute)
	if got := s.Lookup("alice", stale); got != "" {
		t.Fatalf("strict lookup past TTL = %q, want empty", got)
	}
	if got := s.LookupLastKnown("alice"); got != "10.0.0.1:51820" {
		t.Fatalf("last-known past TTL = %q", got)
	}

	// Blacklisted: same split.
	s.MarkFailed("alice", now.Add(time.Second))
	if got := s.Lookup("alice", now.Add(2*time.Second)); got != "" {
		t.Fatalf("strict lookup while blacklisted = %q, want empty", got)
	}
	if got := s.LookupLastKnown("alice"); got != "10.0.0.1:51820" {
		t.Fatalf("last-known while blacklisted = %q", got)
	}
}

func TestStoreMarkFailedUnknownPubkeyNoop(t *testing.T) {
	s := NewStore(90 * time.Second)
	s.MarkFailed("ghost", time.Now())
	if got := len(s.Snapshot()); got != 0 {
		t.Fatalf("snapshot size = %d, want 0", got)
	}
}

func TestStoreSetSelfReady(t *testing.T) {
	s := NewStore(90 * time.Second)
	if _, _, ready := s.Self(); ready {
		t.Fatal("Self before SetSelf should not be ready")
	}
	s.SetSelf("alice-pubkey", 0)
	if _, _, ready := s.Self(); ready {
		t.Fatal("port=0 should not be ready")
	}
	s.SetSelf("alice-pubkey", 51820)
	pub, port, ready := s.Self()
	if !ready || pub != "alice-pubkey" || port != 51820 {
		t.Fatalf("Self = (%q, %d, %v)", pub, port, ready)
	}
	s.SetSelf("", 51820)
	if _, _, ready := s.Self(); ready {
		t.Fatal("empty pubkey should not be ready")
	}
}

func TestStoreSnapshotIsCopy(t *testing.T) {
	s := NewStore(90 * time.Second)
	s.Update("alice", "10.0.0.1:51820", time.Now())
	snap := s.Snapshot()
	delete(snap, "alice")
	if got := s.Lookup("alice", time.Now()); got == "" {
		t.Fatal("mutating snapshot leaked into store")
	}
}

// marshalRaw is shared with beacon_test.go for crafting bytes that bypass
// the Encode() auto-fill, so we can exercise rejection paths.
func marshalRaw(t *testing.T, v any) []byte {
	t.Helper()
	data, err := msgpack.Marshal(v)
	if err != nil {
		t.Fatalf("msgpack marshal: %v", err)
	}
	return data
}
