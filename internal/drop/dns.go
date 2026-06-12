package drop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/dnsprovider"
)

const (
	// chunkPrefix tags TXT values written by tincan so unrelated records at the
	// same name are ignored on read. The trailing digit is a format version.
	chunkPrefix = "tc1"
	// dataPerChunk is the number of base64 characters per TXT record. With the
	// "tc1;<seq>;<total>;" header this keeps every value well under the 255-byte
	// DNS character-string limit.
	dataPerChunk = 220
	// maxDNSChunks caps how many TXT records a directory may occupy: ~100 * 220
	// base64 chars ≈ 16 KB of sealed directory, comfortably more than a large
	// network needs while bounding the DNS response size.
	maxDNSChunks = 100
)

// lookupFunc resolves the TXT records for a name. It mirrors
// (*net.Resolver).LookupTXT so it can be swapped out in tests.
type lookupFunc func(ctx context.Context, name string) ([]string, error)

// DNS is a dead-drop backed by DNS TXT records. Reads use an ordinary DNS
// lookup (no credentials), so any node can sync. Writes require a configured
// provider (e.g. Linode) and are used only by the admin; without one the drop
// is read-only, like the http backend.
//
// The sealed directory is base64-encoded and split into sequence-tagged chunks
// (see chunkBlob). DNS does not preserve order across records at one name, so
// each chunk carries its own index and the total count; reassembly sorts by
// index and rejects an incomplete set. A client that reads a half-updated set
// (publishing is not atomic) fails to reassemble or decrypt, keeps its cached
// directory, and picks up the change on the next sync.
type DNS struct {
	zone     string
	name     string
	fqdn     string
	provider dnsprovider.Provider // nil => read-only
	lookup   lookupFunc
}

func NewDNS(cfg config.DropBackend) (*DNS, error) {
	// DNS names are case-insensitive and providers normalize them (Linode
	// lowercases). Lowercase ours too so the provider's exact-match record
	// lookups in Put don't miss a differently-cased stored name — which would
	// create a duplicate chunk set on every publish and eventually break
	// reassembly.
	zone := strings.ToLower(cfg.Zone)
	recordName := strings.ToLower(cfg.RecordName)
	d := &DNS{
		zone:   zone,
		name:   recordName,
		fqdn:   txtFQDN(recordName, zone),
		lookup: resolverLookup(cfg.Resolver),
	}
	if cfg.Provider != "" {
		p, err := dnsprovider.New(dnsprovider.Config{
			Name:        cfg.Provider,
			Token:       cfg.APIToken,
			AppKey:      cfg.AppKey,
			AppSecret:   cfg.AppSecret,
			ConsumerKey: cfg.ConsumerKey,
			Endpoint:    cfg.Endpoint,
			TTL:         cfg.TTL,
		})
		if err != nil {
			return nil, err
		}
		d.provider = p
	}
	return d, nil
}

func (d *DNS) Name() string { return "dns:" + d.fqdn }

func (d *DNS) Get(ctx context.Context) ([]byte, error) {
	values, err := d.lookup(ctx, d.fqdn)
	if err != nil {
		return nil, mapLookupErr(err)
	}
	return reassembleChunks(values)
}

func (d *DNS) Put(ctx context.Context, data []byte) error {
	if d.provider == nil {
		return fmt.Errorf("dns drop for %s has no provider configured: %w", d.fqdn, ErrReadOnly)
	}
	desired, err := chunkBlob(data)
	if err != nil {
		return err
	}
	existing, err := d.provider.ListTXT(ctx, d.zone, d.name)
	if err != nil {
		return mapProviderErr(err)
	}
	// Reconcile in place: reuse existing records by index, create any shortfall,
	// delete the surplus. This minimizes churn and avoids a window where the
	// record set is empty.
	changed := false
	for i, value := range desired {
		switch {
		case i >= len(existing):
			if err := d.provider.CreateTXT(ctx, d.zone, d.name, value); err != nil {
				return mapProviderErr(err)
			}
			changed = true
		case existing[i].Value != value:
			if err := d.provider.UpdateTXT(ctx, d.zone, existing[i].ID, value); err != nil {
				return mapProviderErr(err)
			}
			changed = true
		}
	}
	for i := len(desired); i < len(existing); i++ {
		if err := d.provider.DeleteTXT(ctx, d.zone, existing[i].ID); err != nil {
			return mapProviderErr(err)
		}
		changed = true
	}
	// Some providers (OVH) stage edits and only serve them after an explicit
	// commit. Flush once, after the batch, and only if we changed anything.
	if changed {
		if f, ok := d.provider.(dnsprovider.Flusher); ok {
			if err := f.Flush(ctx, d.zone); err != nil {
				return mapProviderErr(err)
			}
		}
	}
	return nil
}

func (d *DNS) Stat(ctx context.Context) (Metadata, error) {
	blob, err := d.Get(ctx)
	if err != nil {
		return Metadata{}, err
	}
	// A DNS lookup exposes no reliable per-record mtime, so derive a stable
	// ETag from the content and leave UpdatedAt zero.
	sum := sha256.Sum256(blob)
	return Metadata{Size: int64(len(blob)), ETag: hex.EncodeToString(sum[:8])}, nil
}

// txtFQDN builds the fully-qualified record name to look up. An empty or "@"
// record name targets the zone apex.
func txtFQDN(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")
	if name == "" || name == "@" {
		return zone
	}
	return name + "." + zone
}

// resolverLookup returns a lookupFunc bound to the system resolver, or to a
// custom resolver at addr (host[:port], defaulting to :53) when configured.
func resolverLookup(addr string) lookupFunc {
	if addr == "" {
		return net.DefaultResolver.LookupTXT
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return r.LookupTXT
}

// chunkBlob base64-encodes blob and slices the encoded string into
// sequence-tagged TXT values of the form "tc1;<seq>;<total>;<data>".
func chunkBlob(blob []byte) ([]string, error) {
	encoded := base64.RawURLEncoding.EncodeToString(blob)
	total := (len(encoded) + dataPerChunk - 1) / dataPerChunk
	if total == 0 {
		total = 1 // always emit at least one (possibly empty) chunk
	}
	if total > maxDNSChunks {
		return nil, fmt.Errorf("directory too large for dns drop: needs %d TXT records, max %d", total, maxDNSChunks)
	}
	chunks := make([]string, 0, total)
	for seq := 0; seq < total; seq++ {
		start := seq * dataPerChunk
		end := min(start+dataPerChunk, len(encoded))
		chunks = append(chunks, fmt.Sprintf("%s;%d;%d;%s", chunkPrefix, seq, total, encoded[start:end]))
	}
	return chunks, nil
}

// reassembleChunks selects tincan chunks from values (ignoring any unrelated
// TXT records at the name), orders them by sequence, verifies the set is
// complete, and decodes the concatenation back into the sealed blob. It
// returns ErrNotFound when no tincan chunks are present.
func reassembleChunks(values []string) ([]byte, error) {
	type part struct {
		seq  int
		data string
	}
	var (
		parts []part
		total = -1
	)
	for _, v := range values {
		if !strings.HasPrefix(v, chunkPrefix+";") {
			continue
		}
		fields := strings.SplitN(v, ";", 4)
		if len(fields) != 4 {
			return nil, fmt.Errorf("dns drop: malformed chunk %q", v)
		}
		seq, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, fmt.Errorf("dns drop: bad chunk seq %q: %w", fields[1], err)
		}
		t, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("dns drop: bad chunk total %q: %w", fields[2], err)
		}
		switch {
		case total == -1:
			total = t
		case total != t:
			return nil, fmt.Errorf("dns drop: inconsistent chunk totals (%d vs %d)", total, t)
		}
		parts = append(parts, part{seq: seq, data: fields[3]})
	}
	if len(parts) == 0 {
		return nil, ErrNotFound
	}
	if total <= 0 {
		return nil, fmt.Errorf("dns drop: invalid chunk total %d", total)
	}
	if len(parts) != total {
		return nil, fmt.Errorf("dns drop: incomplete directory: have %d of %d chunks", len(parts), total)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].seq < parts[j].seq })
	var sb strings.Builder
	for i, p := range parts {
		if p.seq != i {
			return nil, fmt.Errorf("dns drop: chunk sequence gap or duplicate near index %d", i)
		}
		sb.WriteString(p.data)
	}
	blob, err := base64.RawURLEncoding.DecodeString(sb.String())
	if err != nil {
		return nil, fmt.Errorf("dns drop: decode chunks: %w", err)
	}
	return blob, nil
}

func mapLookupErr(err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return ErrNotFound
	}
	return err
}

func mapProviderErr(err error) error {
	switch {
	case errors.Is(err, dnsprovider.ErrAuth):
		return ErrAuth
	case errors.Is(err, dnsprovider.ErrNotFound):
		return ErrNotFound
	default:
		return err
	}
}
