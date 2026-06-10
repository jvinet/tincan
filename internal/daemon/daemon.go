package daemon

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const (
	EnvMarker = "_TINCAN_DAEMON"
	EnvConfig = "_TINCAN_CONFIG"
)

// ErrNotRunning reports that there is no live daemon to act on — either the PID
// file is absent or the process it records is gone. Callers can treat it as a
// no-op rather than a failure.
var ErrNotRunning = errors.New("daemon not running")

func IsChild() bool {
	return os.Getenv(EnvMarker) == "1"
}

// Stop signals the daemon recorded in pidFile to shut down (SIGTERM) and waits
// up to `wait` for the process to exit, returning the PID it signaled.
//
// It returns ErrNotRunning when there is nothing to stop. If the process is
// still alive after `wait` — typically because the daemon is finishing an
// in-progress sync before it next checks for signals — Stop returns a non-nil
// error along with the PID, and the caller must not assume the daemon stopped.
func Stop(pidFile string, wait time.Duration) (int, error) {
	pid, err := ReadPID(pidFile)
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNotRunning
	}
	if err != nil {
		return 0, err
	}
	// The daemon holds an exclusive flock on the pid file for its whole life.
	// If we can take that lock, no daemon is running and the recorded PID is
	// stale — refuse to signal it, since after an unclean exit the OS may have
	// recycled it to an unrelated process. The flock is authoritative; a bare
	// kill(pid,0) is not.
	if free, err := pidFileUnlocked(pidFile); err != nil {
		return pid, err
	} else if free {
		return pid, ErrNotRunning
	}
	if !PIDAlive(pid) {
		return pid, ErrNotRunning
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return pid, fmt.Errorf("signal daemon (pid %d): %w", pid, err)
	}
	deadline := time.Now().Add(wait)
	for {
		if !PIDAlive(pid) {
			return pid, nil
		}
		if !time.Now().Before(deadline) {
			return pid, fmt.Errorf("daemon (pid %d) signaled but still running after %s", pid, wait)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func Start(pidFile string, configPath string) (int, error) {
	pf, err := AcquirePIDFile(pidFile, os.Getpid())
	if err != nil {
		return 0, err
	}
	defer pf.Close()
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve executable: %w", err)
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, fmt.Errorf("open /dev/null: %w", err)
	}
	defer devNull.Close()
	files := []*os.File{devNull, devNull, devNull}
	env := append(os.Environ(), EnvMarker+"=1", EnvConfig+"="+configPath)
	proc, err := os.StartProcess(exe, os.Args, &os.ProcAttr{Dir: "/", Env: env, Files: files})
	if err != nil {
		return 0, fmt.Errorf("start daemon child: %w", err)
	}
	pid := proc.Pid
	if err := pf.Write(pid); err != nil {
		_ = proc.Kill()
		return 0, err
	}
	if err := proc.Release(); err != nil {
		return 0, fmt.Errorf("release daemon child: %w", err)
	}
	return pid, nil
}

func BecomeChild() error {
	if _, err := syscall.Setsid(); err != nil {
		return fmt.Errorf("setsid: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}
	syscall.Umask(0o027)
	return nil
}
