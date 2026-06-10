package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type AlreadyRunningError struct {
	PID int
}

func (e *AlreadyRunningError) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("daemon already running with PID %d", e.PID)
	}
	return "daemon already running"
}

type PIDFile struct {
	path string
	file *os.File
}

func AcquirePIDFile(path string, pid int) (*PIDFile, error) {
	if pid == 0 {
		pid = os.Getpid()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create PID directory: %w", err)
	}
	// O_NOFOLLOW: if the final path component is a symlink (e.g. one planted
	// at an attacker-writable pid_file location), refuse rather than follow it
	// and truncate the target as root.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open PID file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		pid := readPIDFromFile(f)
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, &AlreadyRunningError{PID: pid}
		}
		return nil, fmt.Errorf("lock PID file: %w", err)
	}
	pf := &PIDFile{path: path, file: f}
	if err := pf.Write(pid); err != nil {
		_ = pf.CloseRemove()
		return nil, err
	}
	return pf, nil
}

func AcquirePIDFileRetry(path string, pid int, wait time.Duration) (*PIDFile, error) {
	deadline := time.Now().Add(wait)
	for {
		pf, err := AcquirePIDFile(path, pid)
		if err == nil {
			return pf, nil
		}
		var running *AlreadyRunningError
		if !errors.As(err, &running) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (p *PIDFile) Write(pid int) error {
	if _, err := p.file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek PID file: %w", err)
	}
	if err := p.file.Truncate(0); err != nil {
		return fmt.Errorf("truncate PID file: %w", err)
	}
	if _, err := fmt.Fprintf(p.file, "%d\n", pid); err != nil {
		return fmt.Errorf("write PID file: %w", err)
	}
	if err := p.file.Sync(); err != nil {
		return fmt.Errorf("sync PID file: %w", err)
	}
	return nil
}

func (p *PIDFile) Close() error {
	if p.file == nil {
		return nil
	}
	if err := syscall.Flock(int(p.file.Fd()), syscall.LOCK_UN); err != nil {
		_ = p.file.Close()
		return err
	}
	err := p.file.Close()
	p.file = nil
	return err
}

func (p *PIDFile) CloseRemove() error {
	var err error
	if p.file != nil {
		err = p.Close()
	}
	if removeErr := os.Remove(p.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && err == nil {
		err = removeErr
	}
	return err
}

func ReadPID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse PID file: %w", err)
	}
	return pid, nil
}

// pidFileUnlocked reports whether the pid file's advisory lock is free — i.e.
// no live daemon holds it. It briefly takes and releases a non-blocking
// exclusive lock; success means the file is unlocked (stale pid), EWOULDBLOCK
// means a daemon holds it (live). The file must already exist.
func pidFileUnlocked(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return false, fmt.Errorf("open PID file: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return false, nil // a daemon holds the lock → live
		}
		return false, fmt.Errorf("probe PID file lock: %w", err)
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return true, nil
}

func PIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func readPIDFromFile(f *os.File) int {
	if _, err := f.Seek(0, 0); err != nil {
		return 0
	}
	data, err := os.ReadFile(f.Name())
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}
