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
	_, _, err := Read(filepath.Join(t.TempDir(), "cache.bin"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestReadSerialMissingReturnsError(t *testing.T) {
	_, err := ReadSerial(filepath.Join(t.TempDir(), "cache.bin"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestCacheReadWrite(t *testing.T) {
	dir := sampleDir(t)
	path := filepath.Join(t.TempDir(), "state", "cache.bin")
	if err := Write(path, dir, "etag"); err != nil {
		t.Fatal(err)
	}
	got, _, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial != dir.Serial {
		t.Fatalf("serial=%d", got.Serial)
	}
	serial, err := ReadSerial(path)
	if err != nil {
		t.Fatal(err)
	}
	if serial != dir.Serial {
		t.Fatalf("serial file=%d", serial)
	}
	state, err := ReadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastETag != "etag" || state.Serial != dir.Serial {
		t.Fatalf("state=%+v", state)
	}
	if state.LastSync.IsZero() {
		t.Fatal("state LastSync was not set")
	}
	if err := WriteSource(path, dir); err != nil {
		t.Fatal(err)
	}
	source, err := ReadSource(path)
	if err != nil {
		t.Fatal(err)
	}
	if source.Serial != dir.Serial {
		t.Fatalf("source serial=%d", source.Serial)
	}
}

func TestCachePathDerivation(t *testing.T) {
	cachePath := "/var/lib/tincan/cache.bin"
	if got := config.SerialPath(cachePath); got != "/var/lib/tincan/cache.serial" {
		t.Fatalf("serial path=%s", got)
	}
	if got := config.StatePath(cachePath); got != "/var/lib/tincan/state.json" {
		t.Fatalf("state path=%s", got)
	}
	if got := config.SourcePath(cachePath); got != "/var/lib/tincan/directory-source.bin" {
		t.Fatalf("source path=%s", got)
	}
}

func TestReadRejectsCorruptCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.bin")
	if err := os.WriteFile(path, []byte("not msgpack"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(path); err == nil {
		t.Fatal("expected corrupt cache read to fail")
	}
}

func TestReadStateRejectsCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cache.bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.StatePath(path), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(path); err == nil {
		t.Fatal("expected corrupt state read to fail")
	}
}

func TestWriteRejectsInvalidDirectory(t *testing.T) {
	dir := sampleDir(t)
	dir.NetworkCIDR = "not-a-cidr"
	if err := Write(filepath.Join(t.TempDir(), "cache.bin"), dir, ""); err == nil {
		t.Fatal("expected invalid directory write to fail")
	}
}
