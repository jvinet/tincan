package cache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
)

func sampleDir(t *testing.T) directory.Directory {
	t.Helper()
	_, wgPub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return directory.Directory{
		SchemaVersion: directory.SchemaVersion,
		Serial:        42,
		CreatedAt:     time.Now().UTC(),
		NetworkCIDR:   "10.42.0.0/24",
		Nodes:         []directory.Node{{Name: "alice", PublicKey: wgPub, TunnelIP: "10.42.0.1"}},
	}
}

func TestReadMissingReturnsError(t *testing.T) {
	_, _, err := Read(t.TempDir())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestReadSerialMissingReturnsError(t *testing.T) {
	_, err := ReadSerial(t.TempDir())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestCacheReadWrite(t *testing.T) {
	dir := sampleDir(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := Write(stateDir, dir, "etag"); err != nil {
		t.Fatal(err)
	}
	got, _, err := Read(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial != dir.Serial {
		t.Fatalf("serial=%d", got.Serial)
	}
	serial, err := ReadSerial(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if serial != dir.Serial {
		t.Fatalf("serial file=%d", serial)
	}
	state, err := ReadState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastETag != "etag" || state.Serial != dir.Serial {
		t.Fatalf("state=%+v", state)
	}
	if state.LastSync.IsZero() {
		t.Fatal("state LastSync was not set")
	}
	if err := WriteSource(stateDir, dir); err != nil {
		t.Fatal(err)
	}
	source, err := ReadSource(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if source.Serial != dir.Serial {
		t.Fatalf("source serial=%d", source.Serial)
	}
}

func TestWriteRefusesLowerSerial(t *testing.T) {
	stateDir := t.TempDir()
	dir := sampleDir(t) // serial 42
	if err := Write(stateDir, dir, ""); err != nil {
		t.Fatal(err)
	}
	older := dir
	older.Serial = 41
	if err := Write(stateDir, older, ""); err == nil {
		t.Fatal("expected lower-serial write to be refused")
	}
	serial, err := ReadSerial(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if serial != 42 {
		t.Fatalf("serial=%d, want 42", serial)
	}
	// Equal serial stays allowed — re-applying the current directory is the
	// steady state of every daemon iteration.
	if err := Write(stateDir, dir, ""); err != nil {
		t.Fatalf("equal-serial write failed: %v", err)
	}
}

func TestWriteRejectsUnreadableSerial(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(config.SerialPath(stateDir), []byte("not-a-number\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(stateDir, sampleDir(t), ""); err == nil {
		t.Fatal("expected corrupt serial file to block cache write")
	}
	if err := WriteSerialFloor(stateDir, 99); err == nil {
		t.Fatal("expected corrupt serial file to block serial floor write")
	}
}

func TestWriteSerialFloor(t *testing.T) {
	stateDir := t.TempDir()
	if err := WriteSerialFloor(stateDir, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSerial(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("floor 0 should not create the serial file, got %v", err)
	}
	if err := WriteSerialFloor(stateDir, 7); err != nil {
		t.Fatal(err)
	}
	if s, _ := ReadSerial(stateDir); s != 7 {
		t.Fatalf("serial=%d, want 7", s)
	}
	if err := WriteSerialFloor(stateDir, 5); err != nil {
		t.Fatal(err)
	}
	if s, _ := ReadSerial(stateDir); s != 7 {
		t.Fatalf("serial=%d, want 7 after lower floor", s)
	}
	if err := WriteSerialFloor(stateDir, 9); err != nil {
		t.Fatal(err)
	}
	if s, _ := ReadSerial(stateDir); s != 9 {
		t.Fatalf("serial=%d, want 9", s)
	}
}

func TestCachePathDerivation(t *testing.T) {
	stateDir := "/var/lib/tincan"
	if got := config.CachePath(stateDir); got != "/var/lib/tincan/cache.bin" {
		t.Fatalf("cache path=%s", got)
	}
	if got := config.SerialPath(stateDir); got != "/var/lib/tincan/cache.serial" {
		t.Fatalf("serial path=%s", got)
	}
	if got := config.StatePath(stateDir); got != "/var/lib/tincan/state.json" {
		t.Fatalf("state path=%s", got)
	}
	if got := config.SourcePath(stateDir); got != "/var/lib/tincan/directory-source.bin" {
		t.Fatalf("source path=%s", got)
	}
}

func TestReadRejectsCorruptCache(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(config.CachePath(stateDir), []byte("not msgpack"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(stateDir); err == nil {
		t.Fatal("expected corrupt cache read to fail")
	}
}

func TestReadStateRejectsCorruptJSON(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(config.StatePath(stateDir), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(stateDir); err == nil {
		t.Fatal("expected corrupt state read to fail")
	}
}

func TestWriteRejectsInvalidDirectory(t *testing.T) {
	dir := sampleDir(t)
	dir.NetworkCIDR = "not-a-cidr"
	if err := Write(t.TempDir(), dir, ""); err == nil {
		t.Fatal("expected invalid directory write to fail")
	}
}
