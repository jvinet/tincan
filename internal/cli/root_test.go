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

	code := run([]string{
		"-c", configPath,
		"init",
		"--name", "cortex",
		"--drop-type", "http",
		"--state-dir", dir,
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

func TestInitConfigMinimalVsFull(t *testing.T) {
	// Sections/fields the minimal config should omit because they default and
	// are unlikely to be changed; --full-config materializes all of them.
	// ([sync] itself appears in both since --state-dir is an explicit override,
	// but its defaulted interval/pid_file fields should only show up in --full.)
	defaulted := []string{"interface =", "mtu =", "interval =", "pid_file =", "[observe]", "[discovery]"}

	minimal := initConfig(t, false)
	for _, want := range defaulted {
		if strings.Contains(minimal, want) {
			t.Fatalf("minimal config should omit %q:\n%s", want, minimal)
		}
	}
	// Required/likely-changed fields must always be present.
	for _, want := range []string{"[wireguard]", "private_key =", "[directory]", "publisher_key =", "[drop.admin]", "[drop.client]"} {
		if !strings.Contains(minimal, want) {
			t.Fatalf("minimal config missing required %q:\n%s", want, minimal)
		}
	}

	full := initConfig(t, true)
	for _, want := range defaulted {
		if !strings.Contains(full, want) {
			t.Fatalf("full config should include %q:\n%s", want, full)
		}
	}
	// The full config spells out every knob, including the enabled flags at
	// their admin defaults: both observe and discovery on.
	if strings.Contains(full, "enabled = false") {
		t.Fatalf("admin full config should default observe/discovery on, not off:\n%s", full)
	}
	if c := strings.Count(full, "enabled = true"); c != 2 {
		t.Fatalf("full config should surface enabled = true for both [observe] and [discovery], got %d:\n%s", c, full)
	}
}

func TestJoinConfigMinimalOmitsDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-c", configPath,
		"join",
		"--name", "leaf",
		"--drop-type", "file",
		"--generate-key",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code=%d, want 0; stderr=%q", code, stderr.String())
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, unwanted := range []string{"interface =", "mtu =", "[sync]", "[discovery]"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("minimal client config should omit %q:\n%s", unwanted, out)
		}
	}
	// A client never gets an admin drop section.
	if strings.Contains(out, "[drop.admin]") {
		t.Fatalf("client config should not contain [drop.admin]:\n%s", out)
	}
	if !strings.Contains(out, "[drop.client]") {
		t.Fatalf("client config missing [drop.client]:\n%s", out)
	}
}

func initConfig(t *testing.T, full bool) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	args := []string{
		"-c", configPath,
		"init",
		"--name", "cortex",
		"--drop-type", "s3",
		"--state-dir", dir,
	}
	if full {
		args = append(args, "--full-config")
	}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("init exit code=%d, want 0; stderr=%q", code, stderr.String())
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
