package drop

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestFileDropRoundTrip(t *testing.T) {
	d := NewFile(filepath.Join(t.TempDir(), "drop", "directory.bin"))
	want := []byte("directory")
	if err := d.Put(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := d.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	meta, err := d.Stat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if meta.Size != int64(len(want)) {
		t.Fatalf("size=%d", meta.Size)
	}
}

func TestFileDropNotFound(t *testing.T) {
	d := NewFile(filepath.Join(t.TempDir(), "missing", "directory.bin"))
	if _, err := d.Get(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get error=%v, want ErrNotFound", err)
	}
	if _, err := d.Stat(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat error=%v, want ErrNotFound", err)
	}
}

func TestFileDropHonorsCanceledContext(t *testing.T) {
	d := NewFile(filepath.Join(t.TempDir(), "directory.bin"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Get(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get error=%v, want context.Canceled", err)
	}
	if err := d.Put(ctx, []byte("blob")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put error=%v, want context.Canceled", err)
	}
	if _, err := d.Stat(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stat error=%v, want context.Canceled", err)
	}
}
