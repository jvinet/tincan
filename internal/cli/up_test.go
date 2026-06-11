package cli

import (
	"context"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
)

func discardPrinter() *printer { return newPrinter(io.Discard) }

func TestWaitForReconcileFiresAtInterval(t *testing.T) {
	proceed, err := waitForReconcile(context.Background(), nil, nil, nil, nil, 20*time.Millisecond, time.Second, time.Now(), discardPrinter())
	if !proceed || err != nil {
		t.Fatalf("interval expiry should proceed cleanly, got proceed=%v err=%v", proceed, err)
	}
}

func TestWaitForReconcileDebouncesWakeStorm(t *testing.T) {
	wakeCh := make(chan string, 8)
	for range 5 {
		wakeCh <- "beacon"
	}
	start := time.Now()
	// Long interval so only the debounce can release us; minWake small. A
	// storm of wakes must collapse into one reconcile released no sooner than
	// the debounce deadline, not fire immediately on the first wake.
	proceed, err := waitForReconcile(context.Background(), nil, wakeCh, nil, nil, time.Hour, 60*time.Millisecond, start, discardPrinter())
	elapsed := time.Since(start)
	if !proceed || err != nil {
		t.Fatalf("debounced wake should proceed, got proceed=%v err=%v", proceed, err)
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("wake storm was not debounced; released after %v", elapsed)
	}
}

func TestWaitForReconcileWakePastWindowProceedsImmediately(t *testing.T) {
	wakeCh := make(chan string, 1)
	wakeCh <- "beacon"
	// lastReconcile far in the past → debounce window already elapsed.
	start := time.Now()
	proceed, err := waitForReconcile(context.Background(), nil, wakeCh, nil, nil, time.Hour, 10*time.Millisecond, start.Add(-time.Minute), discardPrinter())
	if !proceed || err != nil {
		t.Fatalf("proceed=%v err=%v", proceed, err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("wake past the debounce window should reconcile immediately")
	}
}

func TestWaitForReconcileSIGHUPProceeds(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGHUP
	proceed, err := waitForReconcile(context.Background(), sigCh, nil, nil, nil, time.Hour, time.Hour, time.Now(), discardPrinter())
	if !proceed || err != nil {
		t.Fatalf("SIGHUP should proceed immediately, got proceed=%v err=%v", proceed, err)
	}
}

func TestWaitForReconcileSIGTERMStops(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM
	proceed, err := waitForReconcile(context.Background(), sigCh, nil, nil, nil, time.Hour, time.Hour, time.Now(), discardPrinter())
	if proceed || err != nil {
		t.Fatalf("SIGTERM should stop cleanly, got proceed=%v err=%v", proceed, err)
	}
}

func TestWaitForReconcileContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	proceed, err := waitForReconcile(ctx, nil, nil, nil, nil, time.Hour, time.Hour, time.Now(), discardPrinter())
	if proceed || err == nil {
		t.Fatalf("canceled context should stop with error, got proceed=%v err=%v", proceed, err)
	}
}

func TestWaitForReconcileServicesRelayTicks(t *testing.T) {
	tickCh := make(chan time.Time, 2)
	tickCh <- time.Now()
	tickCh <- time.Now()
	ticks := 0
	// Both buffered ticks must run inline before the interval releases us,
	// and a tick must not itself end the wait.
	proceed, err := waitForReconcile(context.Background(), nil, nil, tickCh, func() { ticks++ }, 50*time.Millisecond, time.Second, time.Now(), discardPrinter())
	if !proceed || err != nil {
		t.Fatalf("interval expiry should proceed cleanly, got proceed=%v err=%v", proceed, err)
	}
	if ticks != 2 {
		t.Fatalf("onTick ran %d times, want 2", ticks)
	}
}

func TestWaitForReconcileNilOnTickIsSafe(t *testing.T) {
	tickCh := make(chan time.Time, 1)
	tickCh <- time.Now()
	proceed, err := waitForReconcile(context.Background(), nil, nil, tickCh, nil, 30*time.Millisecond, time.Second, time.Now(), discardPrinter())
	if !proceed || err != nil {
		t.Fatalf("nil onTick must not panic or stall, got proceed=%v err=%v", proceed, err)
	}
}

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
