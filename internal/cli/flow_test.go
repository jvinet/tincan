package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/internal/keys"
	"github.com/jvinet/tincan/test/fakedrop"
)

func TestPublishDirectoryWithFakeDrop(t *testing.T) {
	cfg, dir := testFlowConfigAndDirectory(t, 1)
	fd := &fakedrop.Drop{}
	if err := publishDirectory(context.Background(), cfg, fd, dir, true); err != nil {
		t.Fatal(err)
	}
	blob, err := fd.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	opened, _, err := directory.Open(blob, cfg.Directory.NetworkIdentity, cfg.Directory.PublisherPubKey)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Serial != dir.Serial {
		t.Fatalf("published serial=%d, want %d", opened.Serial, dir.Serial)
	}
	source, err := cache.ReadSource(cfg.Sync.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if source.Serial != dir.Serial {
		t.Fatalf("source serial=%d, want %d", source.Serial, dir.Serial)
	}
}

func TestFetchSyncDirectoryUsesCacheOnDropFailure(t *testing.T) {
	cfg, dir := testFlowConfigAndDirectory(t, 2)
	if err := cache.Write(cfg.Sync.StateDir, dir, ""); err != nil {
		t.Fatal(err)
	}
	fd := &fakedrop.Drop{GetErr: errors.New("offline")}
	got, fromCache, dropErr, err := fetchSyncDirectory(context.Background(), cfg, fd, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !fromCache {
		t.Fatal("expected cache fallback")
	}
	if dropErr == nil || !strings.Contains(dropErr.Error(), "offline") {
		t.Fatalf("expected drop error to be surfaced, got %v", dropErr)
	}
	if got.Serial != dir.Serial {
		t.Fatalf("serial=%d, want %d", got.Serial, dir.Serial)
	}
}

func TestFetchSyncDirectoryRejectsRollback(t *testing.T) {
	cfg, cached := testFlowConfigAndDirectory(t, 5)
	if err := cache.Write(cfg.Sync.StateDir, cached, ""); err != nil {
		t.Fatal(err)
	}
	stale := cached
	stale.Serial = 4
	blob, err := directory.Seal(stale, cfg.Directory.NetworkIdentity, cfg.Directory.PublisherKey)
	if err != nil {
		t.Fatal(err)
	}
	fd := &fakedrop.Drop{Data: blob}
	_, _, _, err = fetchSyncDirectory(context.Background(), cfg, fd, time.Second)
	if err == nil || !strings.Contains(err.Error(), "stale serial") {
		t.Fatalf("expected stale serial error, got %v", err)
	}
}

func testFlowConfigAndDirectory(t *testing.T, serial uint64) (*config.Config, directory.Directory) {
	t.Helper()
	wgPriv, wgPub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	identity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Wireguard.Name = "alice"
	cfg.Wireguard.PrivateKey = wgPriv
	cfg.Wireguard.PublicKey = wgPub
	cfg.Directory.NetworkIdentity = identity
	cfg.Directory.PublisherPubKey = publisherPub
	cfg.Directory.PublisherKey = publisherPriv
	backend := config.DropBackend{Type: "file", Path: filepath.Join(t.TempDir(), "drop.bin")}
	cfg.Drop = config.DropConfig{Admin: backend, Client: backend}
	cfg.Sync.StateDir = t.TempDir()
	dir := directory.Directory{
		SchemaVersion: directory.SchemaVersion,
		Serial:        serial,
		CreatedAt:     time.Now().UTC(),
		NetworkCIDR:   "10.42.0.0/24",
		Nodes: []directory.Node{{
			Name:      "alice",
			PublicKey: wgPub,
			TunnelIP:  "10.42.0.1",
		}},
	}
	return &cfg, dir
}
