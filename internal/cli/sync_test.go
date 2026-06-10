package cli

import (
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
)

func TestDirectoryStale(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		createdAt time.Time
		maxAge    time.Duration
		wantStale bool
	}{
		{name: "disabled when maxAge is zero", createdAt: now.Add(-100 * time.Hour), maxAge: 0, wantStale: false},
		{name: "fresh within threshold", createdAt: now.Add(-1 * time.Hour), maxAge: 24 * time.Hour, wantStale: false},
		{name: "stale past threshold", createdAt: now.Add(-48 * time.Hour), maxAge: 24 * time.Hour, wantStale: true},
		{name: "zero CreatedAt never stale", createdAt: time.Time{}, maxAge: time.Hour, wantStale: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := directory.Directory{CreatedAt: tc.createdAt}
			_, stale := directoryStale(dir, tc.maxAge)
			if stale != tc.wantStale {
				t.Fatalf("stale = %v, want %v", stale, tc.wantStale)
			}
		})
	}
}
