package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPIDFileAcquireWriteReadAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tincan.pid")
	pf, err := AcquirePIDFile(path, 1234)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := ReadPID(path)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 1234 {
		t.Fatalf("pid=%d", pid)
	}
	if err := pf.CloseRemove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected pidfile removed, got %v", err)
	}
}

func TestPIDFileLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tincan.pid")
	pf, err := AcquirePIDFile(path, 1234)
	if err != nil {
		t.Fatal(err)
	}
	defer pf.CloseRemove()

	_, err = AcquirePIDFile(path, 5678)
	var running *AlreadyRunningError
	if !errors.As(err, &running) || running.PID != 1234 {
		t.Fatalf("expected already-running error with PID 1234, got %v", err)
	}
}

func TestPIDFileCloseReleasesLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tincan.pid")
	pf, err := AcquirePIDFile(path, 1234)
	if err != nil {
		t.Fatal(err)
	}
	if err := pf.Close(); err != nil {
		t.Fatal(err)
	}

	pf2, err := AcquirePIDFile(path, 5678)
	if err != nil {
		t.Fatal(err)
	}
	defer pf2.CloseRemove()
	pid, err := ReadPID(path)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 5678 {
		t.Fatalf("pid=%d", pid)
	}
}

func TestReadPIDMissingAndInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pid")
	if _, err := ReadPID(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
	badPath := filepath.Join(t.TempDir(), "bad.pid")
	if err := os.WriteFile(badPath, []byte("not-a-pid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPID(badPath); err == nil {
		t.Fatal("expected invalid PID parse error")
	}
}

func TestPIDAlive(t *testing.T) {
	if !PIDAlive(os.Getpid()) {
		t.Fatal("expected current PID to be alive")
	}
	if PIDAlive(999999) {
		t.Fatal("expected high PID to be stale")
	}
	if PIDAlive(0) {
		t.Fatal("PID 0 should not be considered alive")
	}
}
