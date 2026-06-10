package cli

import (
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
)

func TestRecordEndpointPushesStampsAndPrunes(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	dir := directory.Directory{Nodes: []directory.Node{
		{Name: "bob", PublicKey: "BOB", TunnelIP: "10.42.0.2"},
		{Name: "carol", PublicKey: "CAROL", TunnelIP: "10.42.0.3"},
	}}
	pushedAt := map[string]time.Time{
		"BOB":  now.Add(-time.Hour),
		"GONE": now.Add(-time.Hour), // no longer in the directory
	}

	recordEndpointPushes(pushedAt, []string{"BOB", "CAROL"}, dir, now)

	if !pushedAt["BOB"].Equal(now) || !pushedAt["CAROL"].Equal(now) {
		t.Fatalf("push times not stamped: %v", pushedAt)
	}
	if _, ok := pushedAt["GONE"]; ok {
		t.Fatal("entry for departed peer was not pruned")
	}
}

func TestRecordEndpointPushesNilMap(t *testing.T) {
	// One-shot `tincan up` has no push-time tracking; must not panic.
	recordEndpointPushes(nil, []string{"BOB"}, directory.Directory{}, time.Now())
}
