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
	r = s.Update("alice", "10.0.0.2:51820", now.Add(60*time.Second))
	if !r.Changed || r.FirstSeen {
		t.Fatalf("endpoint-change should be Changed but not FirstSeen, got %+v", r)
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

func TestStoreMarkFailedAndRevalidate(t *testing.T) {
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
	// Re-validating beacon clears the blacklist.
	r := s.Update("alice", "10.0.0.1:51820", t0.Add(10*time.Second))
	if !r.Changed {
		t.Fatalf("re-validation should report Changed, got %+v", r)
	}
	if r.FirstSeen {
		t.Fatalf("re-validation is not FirstSeen, got %+v", r)
	}
	if got := s.Lookup("alice", t0.Add(11*time.Second)); got != "10.0.0.1:51820" {
		t.Fatalf("re-validated lookup = %q", got)
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
