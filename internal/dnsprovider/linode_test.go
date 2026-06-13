package dnsprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func idFromPath(p string) string {
	parts := strings.Split(strings.TrimRight(p, "/"), "/")
	return parts[len(parts)-1]
}

// linodeMock emulates the subset of the Linode API the provider uses.
type linodeMock struct {
	records     map[int64]linodeRecord
	nextID      int64
	domainCalls int
}

func newLinodeMock() *linodeMock {
	return &linodeMock{records: map[int64]linodeRecord{}, nextID: 1000}
}

func (m *linodeMock) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/domains":
			m.domainCalls++
			_ = json.NewEncoder(w).Encode(domainsResponse{
				Data:  []linodeDomain{{ID: 123, Domain: "example.com"}},
				Pages: 1,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/domains/123/records":
			data := make([]linodeRecord, 0, len(m.records))
			for _, v := range m.records {
				data = append(data, v)
			}
			_ = json.NewEncoder(w).Encode(recordsResponse{Data: data, Pages: 1})
		case r.Method == http.MethodPost && r.URL.Path == "/domains/123/records":
			var rec linodeRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			m.nextID++
			rec.ID = m.nextID
			m.records[rec.ID] = rec
			_ = json.NewEncoder(w).Encode(rec)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/domains/123/records/"):
			id, _ := strconv.ParseInt(idFromPath(r.URL.Path), 10, 64)
			var body linodeRecord
			_ = json.NewDecoder(r.Body).Decode(&body)
			rec := m.records[id]
			rec.Target = body.Target
			if body.TTLSec != 0 {
				rec.TTLSec = body.TTLSec
			}
			m.records[id] = rec
			_ = json.NewEncoder(w).Encode(rec)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/domains/123/records/"):
			id, _ := strconv.ParseInt(idFromPath(r.URL.Path), 10, 64)
			delete(m.records, id)
			_ = json.NewEncoder(w).Encode(struct{}{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestLinodeRoundTrip(t *testing.T) {
	mock := newLinodeMock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	p, err := New(Config{Name: "linode", Token: "tok", TTL: 300, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := p.CreateTXT(ctx, "example.com", "_tincan", "tc1;0;2;AAA"); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateTXT(ctx, "example.com", "_tincan", "tc1;1;2;BBB"); err != nil {
		t.Fatal(err)
	}

	list, err := p.ListTXT(ctx, "example.com", "_tincan")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 records, got %d", len(list))
	}

	if err := p.UpdateTXT(ctx, "example.com", list[0].ID, "tc1;0;2;ZZZ"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteTXT(ctx, "example.com", list[1].ID); err != nil {
		t.Fatal(err)
	}

	list, err = p.ListTXT(ctx, "example.com", "_tincan")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 record after delete, got %d", len(list))
	}
	if list[0].Value != "tc1;0;2;ZZZ" {
		t.Fatalf("update not applied: %q", list[0].Value)
	}

	// The domain id should have been resolved once and cached across the five
	// operations above.
	if mock.domainCalls != 1 {
		t.Fatalf("domain id resolved %d times, want 1 (cached)", mock.domainCalls)
	}
}

func TestLinodeAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "linode", Token: "bad", BaseURL: srv.URL})
	if _, err := p.ListTXT(context.Background(), "example.com", "_tincan"); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestLinodeDomainNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/domains" {
			_ = json.NewEncoder(w).Encode(domainsResponse{Data: nil, Pages: 1})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "linode", Token: "tok", BaseURL: srv.URL})
	if err := p.CreateTXT(context.Background(), "absent.example", "_tincan", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestNewUnsupportedProvider(t *testing.T) {
	if _, err := New(Config{Name: "gandi"}); err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	if Supported("gandi") {
		t.Fatal("Supported() should reject an unknown provider")
	}
	for _, name := range []string{"linode", "digitalocean", "cloudflare", "desec", "hetzner", "route53", "ovh"} {
		if !Supported(name) {
			t.Fatalf("Supported(%q) = false, want true", name)
		}
	}
}
