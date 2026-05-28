package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWithoutArgsPrintsHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code=%d, want 0; stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Usage: tincan") {
		t.Fatalf("help output missing usage:\n%s", out)
	}
	if !strings.Contains(out, "Commands:") {
		t.Fatalf("help output missing commands:\n%s", out)
	}
	if strings.Contains(out, "expected one of") {
		t.Fatalf("help output contains parse error:\n%s", out)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty", stderr.String())
	}
}

func TestRunInitBindsCommandContext(t *testing.T) {
	var stdout, stderr bytes.Buffer
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	cachePath := filepath.Join(dir, "cache.bin")

	code := run([]string{
		"-c", configPath,
		"init",
		"--name", "cortex",
		"--drop-type", "http",
		"--cache", cachePath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code=%d, want 0; stderr=%q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "couldn't find binding") {
		t.Fatalf("stderr contains Kong binding error: %q", stderr.String())
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("config was not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "directory-source.bin")); err != nil {
		t.Fatalf("source directory was not written: %v", err)
	}
}
