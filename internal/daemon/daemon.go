package daemon

import (
	"fmt"
	"os"
	"syscall"
)

const (
	EnvMarker = "_TINCAN_DAEMON"
	EnvConfig = "_TINCAN_CONFIG"
)

func IsChild() bool {
	return os.Getenv(EnvMarker) == "1"
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
