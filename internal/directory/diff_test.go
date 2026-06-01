package directory

import (
	"strings"
	"testing"
	"time"
)

func dir(serial uint64, cidr string, nodes ...Node) Directory {
	return Directory{SchemaVersion: SchemaVersion, Serial: serial, NetworkCIDR: cidr, Nodes: nodes}
}

func TestCompareObservedAtRefreshOnly(t *testing.T) {
	t1 := time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC)
	t2 := t1.Add(15 * time.Minute)
	old := dir(326, "10.42.0.0/24",
		Node{Name: "laptop", PublicKey: "pk-laptop", TunnelIP: "10.42.0.1", ObservedEndpoint: "203.0.113.7:51820", ObservedAt: t1},
	)
	updated := dir(327, "10.42.0.0/24",
		Node{Name: "laptop", PublicKey: "pk-laptop", TunnelIP: "10.42.0.1", ObservedEndpoint: "203.0.113.7:51820", ObservedAt: t2},
	)

	d := Compare(old, updated)
	if d.Empty() {
		t.Fatal("expected a change, got empty diff")
	}
	if len(d.Changed) != 1 || len(d.Changed[0].Fields) != 1 {
		t.Fatalf("expected one node with one field change, got %+v", d.Changed)
	}
	f := d.Changed[0].Fields[0]
	if f.Field != "observed_at" {
		t.Fatalf("expected observed_at field, got %q", f.Field)
	}
	if got, want := d.Summary(), "laptop: observed_at refreshed (+15m0s)"; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
	// The endpoint string must not appear: the whole point is to show that
	// routing did not change.
	if strings.Contains(d.Summary(), "203.0.113.7") {
		t.Fatalf("refresh summary should not mention the unchanged endpoint: %q", d.Summary())
	}
}

func TestCompareObservedEndpointChanged(t *testing.T) {
	t1 := time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC)
	old := dir(1, "10.42.0.0/24",
		Node{Name: "laptop", PublicKey: "pk-laptop", TunnelIP: "10.42.0.1", ObservedEndpoint: "203.0.113.7:51820", ObservedAt: t1},
	)
	updated := dir(2, "10.42.0.0/24",
		Node{Name: "laptop", PublicKey: "pk-laptop", TunnelIP: "10.42.0.1", ObservedEndpoint: "198.51.100.4:33001", ObservedAt: t1.Add(time.Minute)},
	)

	d := Compare(old, updated)
	// observed_at also advanced, but a real endpoint change should report only
	// the endpoint transition, not a redundant timestamp refresh.
	if len(d.Changed) != 1 || len(d.Changed[0].Fields) != 1 {
		t.Fatalf("expected one node with one field change, got %+v", d.Changed)
	}
	if got, want := d.Summary(), "laptop: observed_endpoint 203.0.113.7:51820 -> 198.51.100.4:33001"; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
}

func TestCompareObservedEndpointSetAndCleared(t *testing.T) {
	at := time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC)
	never := dir(1, "10.42.0.0/24", Node{Name: "n", PublicKey: "pk", TunnelIP: "10.42.0.1"})
	seen := dir(2, "10.42.0.0/24", Node{Name: "n", PublicKey: "pk", TunnelIP: "10.42.0.1", ObservedEndpoint: "203.0.113.7:51820", ObservedAt: at})

	if got, want := Compare(never, seen).Summary(), "n: observed_endpoint (none) -> 203.0.113.7:51820"; got != want {
		t.Fatalf("set summary = %q, want %q", got, want)
	}
	if got, want := Compare(seen, never).Summary(), "n: observed_endpoint 203.0.113.7:51820 -> (none)"; got != want {
		t.Fatalf("clear summary = %q, want %q", got, want)
	}
}

func TestCompareAddRemove(t *testing.T) {
	a := Node{Name: "alice", PublicKey: "pk-a", TunnelIP: "10.42.0.1"}
	b := Node{Name: "bob", PublicKey: "pk-b", TunnelIP: "10.42.0.2"}
	d := Compare(dir(1, "10.42.0.0/24", a), dir(2, "10.42.0.0/24", a, b))
	if got, want := d.Summary(), "added bob"; got != want {
		t.Fatalf("add summary = %q, want %q", got, want)
	}
	d = Compare(dir(2, "10.42.0.0/24", a, b), dir(3, "10.42.0.0/24", a))
	if got, want := d.Summary(), "removed bob"; got != want {
		t.Fatalf("remove summary = %q, want %q", got, want)
	}
}

func TestCompareRenameMatchesByPublicKey(t *testing.T) {
	old := dir(1, "10.42.0.0/24", Node{Name: "old-name", PublicKey: "pk-stable", TunnelIP: "10.42.0.1"})
	updated := dir(2, "10.42.0.0/24", Node{Name: "new-name", PublicKey: "pk-stable", TunnelIP: "10.42.0.1"})
	d := Compare(old, updated)
	if len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatalf("rename should not be add+remove, got added=%v removed=%v", d.Added, d.Removed)
	}
	if got, want := d.Summary(), "new-name: name old-name -> new-name"; got != want {
		t.Fatalf("rename summary = %q, want %q", got, want)
	}
}

func TestComparePSKNeverLeaksValue(t *testing.T) {
	const secret = "super-secret-preshared-key-value"
	old := dir(1, "10.42.0.0/24", Node{Name: "n", PublicKey: "pk", TunnelIP: "10.42.0.1"})
	updated := dir(2, "10.42.0.0/24", Node{Name: "n", PublicKey: "pk", TunnelIP: "10.42.0.1", PSK: secret})

	for _, tc := range []struct {
		name       string
		a, b       Directory
		wantDetail string
	}{
		{"set", old, updated, "set"},
		{"cleared", updated, old, "cleared"},
		{"changed", updated, dir(3, "10.42.0.0/24", Node{Name: "n", PublicKey: "pk", TunnelIP: "10.42.0.1", PSK: secret + "-rotated"}), "changed"},
	} {
		d := Compare(tc.a, tc.b)
		sum := d.Summary()
		if !strings.Contains(sum, "psk "+tc.wantDetail) {
			t.Fatalf("%s: summary %q missing %q", tc.name, sum, "psk "+tc.wantDetail)
		}
		if strings.Contains(sum, secret) {
			t.Fatalf("%s: PSK value leaked into summary %q", tc.name, sum)
		}
	}
}

func TestCompareCIDRChange(t *testing.T) {
	d := Compare(dir(1, "10.42.0.0/24"), dir(2, "10.43.0.0/24"))
	if got, want := d.Summary(), "network_cidr 10.42.0.0/24 -> 10.43.0.0/24"; got != want {
		t.Fatalf("cidr summary = %q, want %q", got, want)
	}
}

func TestCompareMetadataOnly(t *testing.T) {
	n := Node{Name: "n", PublicKey: "pk", TunnelIP: "10.42.0.1"}
	// Same nodes/CIDR, only the serial differs (a pure bump).
	d := Compare(dir(5, "10.42.0.0/24", n), dir(6, "10.42.0.0/24", n))
	if !d.Empty() {
		t.Fatalf("expected empty diff, got %+v", d)
	}
	if got, want := d.Summary(), "metadata only (serial/timestamp)"; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
}

func TestCompareMultipleNodesAndFields(t *testing.T) {
	at := time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC)
	old := dir(1, "10.42.0.0/24",
		Node{Name: "a", PublicKey: "pk-a", TunnelIP: "10.42.0.1", ObservedEndpoint: "203.0.113.7:51820", ObservedAt: at},
		Node{Name: "b", PublicKey: "pk-b", TunnelIP: "10.42.0.2"},
	)
	updated := dir(2, "10.42.0.0/24",
		Node{Name: "a", PublicKey: "pk-a", TunnelIP: "10.42.0.1", ObservedEndpoint: "203.0.113.7:51820", ObservedAt: at.Add(15 * time.Minute)},
		Node{Name: "b", PublicKey: "pk-b", TunnelIP: "10.42.0.2", ObservedEndpoint: "198.51.100.4:7000", ObservedAt: at.Add(time.Minute)},
	)
	d := Compare(old, updated)
	if got, want := d.Summary(), "a: observed_at refreshed (+15m0s); b: observed_endpoint (none) -> 198.51.100.4:7000"; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
}
