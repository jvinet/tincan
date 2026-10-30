package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jvinet/tincan/internal/cache"
	"github.com/jvinet/tincan/internal/directory"
	"github.com/jvinet/tincan/test/fakedrop"
)

func runAdminCLI(t *testing.T, configPath string, args ...string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run(append([]string{"-c", configPath}, args...), &stdout, &stderr); code != 0 {
		t.Fatalf("%v: exit %d: %s", args, code, stderr.String())
	}
}

func TestDeferredAdminEditsAccumulate(t *testing.T) {
	path, cfg := setDomainFixture(t, nil)
	runAdminCLI(t, path, "set-domain", "vpn", "--no-publish")
	for _, name := range []string{"bob", "carol"} {
		runAdminCLI(t, path, "add-node", "--name", name, "--no-publish", "--bootstrap", filepath.Join(t.TempDir(), name+".json"))
	}
	runAdminCLI(t, path, "remove-node", "--name", "bob", "--no-publish")
	if remote := publishedDirectory(t, cfg); remote.Serial != 1 || remote.Domain != "" || len(remote.Nodes) != 1 {
		t.Fatalf("deferred edits leaked to the drop: %+v", remote)
	}
	// Background observation must not accidentally publish staged membership.
	// A nil manager makes this fail if observation gets as far as querying WG.
	if err := runAdminObservation(context.Background(), cfg, nil, 1, discardPrinter(), nil); err != nil {
		t.Fatal(err)
	}
	runAdminCLI(t, path, "publish")
	remote := publishedDirectory(t, cfg)
	if remote.Domain != "vpn" || len(remote.Nodes) != 2 || remote.Serial != 2 {
		t.Fatalf("staged edits were lost: %+v", remote)
	}
	carol, _, ok := nodeByName(remote, "carol")
	if !ok || carol.TunnelIP != "10.42.0.3" {
		t.Fatalf("staged IP allocations were not preserved: %+v", remote.Nodes)
	}
}

func TestAutomaticPublishPreservesDeferredAdd(t *testing.T) {
	path, cfg := setDomainFixture(t, nil)
	runAdminCLI(t, path, "add-node", "--name", "bob", "--no-publish", "--bootstrap", filepath.Join(t.TempDir(), "bob.json"))
	runAdminCLI(t, path, "add-node", "--name", "carol", "--bootstrap", filepath.Join(t.TempDir(), "carol.json"))
	if remote := publishedDirectory(t, cfg); len(remote.Nodes) != 3 || remote.Serial != 2 {
		t.Fatalf("automatic publish dropped the staged node: %+v", remote)
	}
}

func TestAdminMutationsRefuseUnverifiedRemote(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "unreadable", true: "invalid"}[invalid], func(t *testing.T) {
			cfg, source := testFlowConfigAndDirectory(t, 2)
			remote := source
			remote.Serial = 3
			blob, err := directory.Seal(remote, cfg.Directory.PublisherKey)
			if err != nil {
				t.Fatal(err)
			}
			fd := &fakedrop.Drop{Data: blob, GetErr: errors.New("read unavailable")}
			if invalid {
				fd.GetErr = nil
				fd.Data = []byte("invalid ciphertext")
			}
			before := append([]byte(nil), fd.Data...)
			if _, err := saveAdminDirectory(context.Background(), cfg, fd, source, false); err == nil || !strings.Contains(err.Error(), "--force") {
				t.Fatalf("expected refusal before upload, got %v", err)
			}
			if !bytes.Equal(fd.Data, before) {
				t.Fatal("refused mutation changed the drop")
			}
			// Offline staging is still permitted; publishing remains explicit.
			if _, err := saveAdminDirectory(context.Background(), cfg, fd, source, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPreparePublishSerialHonorsLocalFloor(t *testing.T) {
	cfg, source := testFlowConfigAndDirectory(t, 2)
	if err := cache.WriteSerialFloor(cfg.Sync.StateDir, 8); err != nil {
		t.Fatal(err)
	}
	if err := preparePublishSerial(cfg, &source, directory.Directory{Serial: 3}, nil, false); err != nil {
		t.Fatal(err)
	}
	if source.Serial != 9 {
		t.Fatalf("serial = %d, want 9", source.Serial)
	}
}

func TestFailedUploadReservesSerial(t *testing.T) {
	cfg, source := testFlowConfigAndDirectory(t, 1)
	if err := cache.Write(cfg.Sync.StateDir, source, ""); err != nil {
		t.Fatal(err)
	}
	fd := &fakedrop.Drop{PutErr: errors.New("upload acknowledgment lost")}
	if _, err := saveAdminDirectory(context.Background(), cfg, fd, source, false); err == nil {
		t.Fatal("expected upload failure")
	}
	floor, err := cache.ReadPublishSerial(cfg.Sync.StateDir)
	if err != nil || floor != 2 {
		t.Fatalf("reserved serial = %d, err = %v", floor, err)
	}
	// A reservation is not an accepted-directory floor. Offline sync must
	// still be able to refresh/apply the last good cache after a failed put.
	fd.GetErr = errors.New("offline")
	cached, fromCache, _, err := fetchSyncDirectory(context.Background(), cfg, fd, 0)
	if err != nil || !fromCache {
		t.Fatalf("offline cache unavailable after failed upload: %v", err)
	}
	if err := cache.Write(cfg.Sync.StateDir, cached, ""); err != nil {
		t.Fatal(err)
	}
	fd.GetErr = nil
	fd.PutErr = nil
	published, err := saveAdminDirectory(context.Background(), cfg, fd, source, false)
	if err != nil {
		t.Fatal(err)
	}
	if published.Serial != 3 {
		t.Fatalf("retried upload reused a serial: %d", published.Serial)
	}
}

func TestConcurrentLocalAdminAddsAreSerialized(t *testing.T) {
	path, cfg := setDomainFixture(t, nil)
	var wg sync.WaitGroup
	for _, name := range []string{"bob", "carol"} {
		artifact := filepath.Join(t.TempDir(), name+".json")
		wg.Add(1)
		go func() {
			defer wg.Done()
			runAdminCLI(t, path, "add-node", "--name", name, "--bootstrap", artifact)
		}()
	}
	wg.Wait()
	if remote := publishedDirectory(t, cfg); remote.Serial != 3 || len(remote.Nodes) != 3 {
		t.Fatalf("concurrent mutation was lost: %+v", remote)
	}
}
