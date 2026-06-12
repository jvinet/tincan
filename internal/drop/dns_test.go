package drop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/dnsprovider"
)

// fakeProvider is an in-memory dnsprovider.Provider that records call counts.
type fakeProvider struct {
	records []dnsprovider.TXTRecord
	nextID  int
	creates int
	updates int
	deletes int
}

func (f *fakeProvider) ListTXT(context.Context, string, string) ([]dnsprovider.TXTRecord, error) {
	out := make([]dnsprovider.TXTRecord, len(f.records))
	copy(out, f.records)
	return out, nil
}

func (f *fakeProvider) CreateTXT(_ context.Context, _, _, value string) error {
	f.nextID++
	f.records = append(f.records, dnsprovider.TXTRecord{ID: fmt.Sprintf("r%d", f.nextID), Value: value})
	f.creates++
	return nil
}

func (f *fakeProvider) UpdateTXT(_ context.Context, _, id, value string) error {
	for i := range f.records {
		if f.records[i].ID == id {
			f.records[i].Value = value
			f.updates++
			return nil
		}
	}
	return fmt.Errorf("fake: no record %q", id)
}

func (f *fakeProvider) DeleteTXT(_ context.Context, _, id string) error {
	for i := range f.records {
		if f.records[i].ID == id {
			f.records = append(f.records[:i], f.records[i+1:]...)
			f.deletes++
			return nil
		}
	}
	return fmt.Errorf("fake: no record %q", id)
}

// lookup mirrors net.LookupTXT, reading the current record values.
func (f *fakeProvider) lookup(context.Context, string) ([]string, error) {
	vals := make([]string, len(f.records))
	for i, r := range f.records {
		vals[i] = r.Value
	}
	return vals, nil
}

func dnsBackedBy(f *fakeProvider) *DNS {
	return &DNS{zone: "example.com", name: "_tincan", fqdn: "_tincan.example.com", provider: f, lookup: f.lookup}
}

func TestDNSChunkRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 100, dataPerChunk - 1, dataPerChunk, dataPerChunk + 1, 5000} {
		blob := make([]byte, size)
		for i := range blob {
			blob[i] = byte(i % 251)
		}
		chunks, err := chunkBlob(blob)
		if err != nil {
			t.Fatalf("size %d: chunkBlob: %v", size, err)
		}
		for _, c := range chunks {
			if len(c) > 255 {
				t.Fatalf("size %d: chunk %d bytes exceeds DNS limit", size, len(c))
			}
		}
		got, err := reassembleChunks(chunks)
		if err != nil {
			t.Fatalf("size %d: reassemble: %v", size, err)
		}
		if !bytes.Equal(got, blob) {
			t.Fatalf("size %d: round-trip mismatch", size)
		}
	}
}

func TestDNSReassembleOrderIndependent(t *testing.T) {
	blob := bytes.Repeat([]byte("the quick brown fox; "), 40)
	chunks, err := chunkBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 3 {
		t.Fatalf("want >=3 chunks for a meaningful shuffle, got %d", len(chunks))
	}
	// Reverse to simulate a resolver returning records out of order.
	for i, j := 0, len(chunks)-1; i < j; i, j = i+1, j-1 {
		chunks[i], chunks[j] = chunks[j], chunks[i]
	}
	got, err := reassembleChunks(chunks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatal("mismatch after shuffle")
	}
}

func TestDNSReassembleIgnoresForeignTXT(t *testing.T) {
	blob := []byte("hello directory")
	chunks, err := chunkBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	values := append([]string{"v=spf1 include:_spf.example.com ~all"}, chunks...)
	values = append(values, "google-site-verification=abc123")
	got, err := reassembleChunks(values)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatal("foreign TXT records broke reassembly")
	}
}

func TestDNSReassembleIncomplete(t *testing.T) {
	chunks, err := chunkBlob(bytes.Repeat([]byte("x"), 1000))
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("want >=2 chunks, got %d", len(chunks))
	}
	if _, err := reassembleChunks(chunks[1:]); err == nil {
		t.Fatal("expected error for missing chunk")
	}
}

func TestDNSReassembleNoChunks(t *testing.T) {
	if _, err := reassembleChunks([]string{"unrelated", "txt"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestDNSChunkTooLarge(t *testing.T) {
	// Enough raw bytes that base64 needs more than maxDNSChunks chunks.
	huge := make([]byte, (maxDNSChunks+5)*dataPerChunk)
	if _, err := chunkBlob(huge); err == nil {
		t.Fatal("expected too-large error")
	}
}

func TestDNSPutReadOnlyWithoutProvider(t *testing.T) {
	d := &DNS{fqdn: "_tincan.example.com"}
	if err := d.Put(context.Background(), []byte("blob")); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("got %v, want ErrReadOnly", err)
	}
}

func TestDNSPutThenGet(t *testing.T) {
	f := &fakeProvider{}
	d := dnsBackedBy(f)
	blob := bytes.Repeat([]byte("directory-blob;"), 50) // spans multiple chunks
	ctx := context.Background()
	if err := d.Put(ctx, blob); err != nil {
		t.Fatal(err)
	}
	wantChunks, _ := chunkBlob(blob)
	if f.creates != len(wantChunks) || f.updates != 0 || f.deletes != 0 {
		t.Fatalf("creates=%d updates=%d deletes=%d, want creates=%d", f.creates, f.updates, f.deletes, len(wantChunks))
	}
	got, err := d.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatal("Put/Get round-trip mismatch")
	}
}

func TestDNSPutReconcileShrinks(t *testing.T) {
	f := &fakeProvider{}
	d := dnsBackedBy(f)
	ctx := context.Background()

	big := bytes.Repeat([]byte("x"), 3000)
	if err := d.Put(ctx, big); err != nil {
		t.Fatal(err)
	}
	bigChunks := f.creates
	if bigChunks < 2 {
		t.Fatalf("want a multi-chunk directory, got %d", bigChunks)
	}
	f.creates, f.updates, f.deletes = 0, 0, 0

	small := []byte("tiny")
	if err := d.Put(ctx, small); err != nil {
		t.Fatal(err)
	}
	smallChunks, _ := chunkBlob(small)
	if f.deletes != bigChunks-len(smallChunks) {
		t.Fatalf("deletes=%d, want %d", f.deletes, bigChunks-len(smallChunks))
	}
	got, err := d.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, small) {
		t.Fatal("shrink reconcile produced wrong directory")
	}
}

// flushingProvider is a fakeProvider that also implements dnsprovider.Flusher,
// counting Flush calls so the drop's commit behavior can be asserted.
type flushingProvider struct {
	*fakeProvider
	flushes int
}

func (f *flushingProvider) Flush(_ context.Context, _ string) error {
	f.flushes++
	return nil
}

// TestDNSPutFlushesOnChange verifies the drop commits a Flusher provider's
// staged writes exactly once per Put that changes records, and not at all when
// a Put is a no-op (so OVH's zone refresh isn't fired needlessly).
func TestDNSPutFlushesOnChange(t *testing.T) {
	fp := &flushingProvider{fakeProvider: &fakeProvider{}}
	d := &DNS{zone: "example.com", name: "_tincan", fqdn: "_tincan.example.com", provider: fp, lookup: fp.lookup}
	ctx := context.Background()

	if err := d.Put(ctx, []byte("the original directory blob")); err != nil {
		t.Fatal(err)
	}
	if fp.flushes != 1 {
		t.Fatalf("flushes after creating records = %d, want 1", fp.flushes)
	}

	// Re-publishing identical bytes changes nothing: nothing to commit.
	if err := d.Put(ctx, []byte("the original directory blob")); err != nil {
		t.Fatal(err)
	}
	if fp.flushes != 1 {
		t.Fatalf("flushes after a no-op Put = %d, want 1 (no change ⇒ no refresh)", fp.flushes)
	}

	// Different bytes update the records, which must commit again.
	if err := d.Put(ctx, []byte("a wholly different directory blob")); err != nil {
		t.Fatal(err)
	}
	if fp.flushes != 2 {
		t.Fatalf("flushes after changed Put = %d, want 2", fp.flushes)
	}
}

// DNS names are case-insensitive and providers normalize them; NewDNS must
// lowercase the zone and record name so provider record lookups in Put don't
// miss a differently-cased stored name (which would duplicate the chunk set).
func TestNewDNSLowercasesNames(t *testing.T) {
	d, err := NewDNS(config.DropBackend{Type: "dns", Zone: "Example.COM", RecordName: "_Tincan"})
	if err != nil {
		t.Fatal(err)
	}
	if d.zone != "example.com" {
		t.Fatalf("zone = %q, want lowercased", d.zone)
	}
	if d.name != "_tincan" {
		t.Fatalf("name = %q, want lowercased", d.name)
	}
}

func TestDNSGetNotFound(t *testing.T) {
	d := &DNS{
		fqdn:   "_tincan.example.com",
		lookup: func(context.Context, string) ([]string, error) { return nil, nil },
	}
	if _, err := d.Get(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}
