package daemon

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestStopNotRunning(t *testing.T) {
	// No PID file at all.
	missing := filepath.Join(t.TempDir(), "missing.pid")
	if _, err := Stop(missing, time.Second); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning for missing pidfile, got %v", err)
	}

	// PID file naming a process that is not alive.
	dead := filepath.Join(t.TempDir(), "dead.pid")
	if err := os.WriteFile(dead, []byte("999999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Stop(dead, time.Second); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning for dead pid, got %v", err)
	}

	// PID file naming a *live* process (our own) but not flock-held: a stale
	// file left by a crashed daemon whose PID the OS recycled. Stop must not
	// signal it — the absence of the lock is the proof no daemon is running.
	recycled := filepath.Join(t.TempDir(), "recycled.pid")
	if err := os.WriteFile(recycled, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Stop(recycled, time.Second); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning for unlocked (recycled) pid, got %v", err)
	}
}

func TestStopSignalsAndWaitsForExit(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	// Reap the child as soon as it exits. A zombie still answers kill(pid, 0),
	// so without this PIDAlive would report it alive and Stop would time out.
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	// Hold the pid-file flock to stand in for a live daemon: Stop now treats
	// the lock, not just the recorded pid, as proof the daemon is running.
	path := filepath.Join(t.TempDir(), "tincan.pid")
	pf, err := AcquirePIDFile(path, cmd.Process.Pid)
	if err != nil {
		t.Fatalf("acquire pid file: %v", err)
	}
	defer pf.Close()

	pid, err := Stop(path, 5*time.Second)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if pid != cmd.Process.Pid {
		t.Fatalf("Stop returned pid %d, want %d", pid, cmd.Process.Pid)
	}
	if PIDAlive(cmd.Process.Pid) {
		t.Fatalf("process %d still alive after Stop", cmd.Process.Pid)
	}

	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("child did not exit after SIGTERM")
	}
}

func TestStopReturnsErrorWhenProcessSurvives(t *testing.T) {
	// A process that ignores SIGTERM lets us exercise the timeout path without
	// waiting on real iteration latency.
	cmd := exec.Command("sh", "-c", "trap '' TERM; sleep 60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sh: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	path := filepath.Join(t.TempDir(), "tincan.pid")
	pf, err := AcquirePIDFile(path, cmd.Process.Pid)
	if err != nil {
		t.Fatalf("acquire pid file: %v", err)
	}
	defer pf.Close()

	pid, err := Stop(path, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error when process ignores SIGTERM")
	}
	if errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected a timeout error, got ErrNotRunning")
	}
	if pid != cmd.Process.Pid {
		t.Fatalf("Stop returned pid %d, want %d", pid, cmd.Process.Pid)
	}
}
