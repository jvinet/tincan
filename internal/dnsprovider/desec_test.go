package dnsprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// desecMock emulates the subset of the deSEC RRset API the provider uses: GET,
// PUT (upsert), and DELETE of a single TXT RRset at /domains/<domain>/rrsets/
// <subname>/TXT/. RRsets are stored under the URL subname ("@" for the apex)
// holding the quoted record strings exactly as the API would. Any request for a
// different domain is a 404, emulating an unknown domain.
type desecMock struct {
	domain string
	rrsets map[string][]string // url subname -> quoted records
}

func newDesecMock() *desecMock {
	return &desecMock{domain: "example.com", rrsets: map[string][]string{}}
}

// key maps an RRset's body subname ("" for the apex) to the storage key, which
// matches the URL placeholder ("@" for the apex).
func (m *desecMock) key(bodySubname string) string {
	if bodySubname == "" {
		return "@"
	}
	return bodySubname
}

func desecNotFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"detail":"Not found."}`))
}

func (m *desecMock) handler() http.HandlerFunc {
	collection := "/domains/" + m.domain + "/rrsets/"
	return func(w http.ResponseWriter, r *http.Request) {
		// POST to the collection creates a new RRset.
		if r.Method == http.MethodPost && r.URL.Path == collection {
			var rr desecRRset
			_ = json.NewDecoder(r.Body).Decode(&rr)
			m.rrsets[m.key(rr.Subname)] = rr.Records
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(rr)
			return
		}
		if !strings.HasPrefix(r.URL.Path, collection) || !strings.HasSuffix(r.URL.Path, "/TXT/") {
			desecNotFound(w)
			return
		}
		sub := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, collection), "/TXT/")
		switch r.Method {
		case http.MethodGet:
			recs, ok := m.rrsets[sub]
			if !ok {
				desecNotFound(w)
				return
			}
			_ = json.NewEncoder(w).Encode(desecRRset{Subname: sub, Type: "TXT", TTL: 3600, Records: recs})
		case http.MethodPut:
			// Emulate the restrictive (DRF-default) semantics: detail PUT only
			// modifies an existing RRset, 404ing on a missing one — which forces
			// the provider's POST-create fallback.
			if _, ok := m.rrsets[sub]; !ok {
				desecNotFound(w)
				return
			}
			var rr desecRRset
			_ = json.NewDecoder(r.Body).Decode(&rr)
			m.rrsets[sub] = rr.Records
			_ = json.NewEncoder(w).Encode(rr)
		case http.MethodDelete:
			delete(m.rrsets, sub)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// TestDeSECReplaceTXT covers the path the dns drop actually uses: a single
// atomic replace of the whole RRset. It checks values are stored quoted, that a
// second replace fully supersedes the first, and that replacing one name leaves
// an unrelated RRset untouched (i.e. the write is scoped, not a bulk wipe).
func TestDeSECReplaceTXT(t *testing.T) {
	mock := newDesecMock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	p, err := New(Config{Name: "desec", Token: "tok", TTL: 3600, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	r := p.(Replacer)
	ctx := context.Background()

	// An unrelated RRset at another name that must survive the replace below.
	if err := r.ReplaceTXT(ctx, "example.com", "other", []string{"keep-me"}); err != nil {
		t.Fatal(err)
	}

	if err := r.ReplaceTXT(ctx, "example.com", "_tincan", []string{"tc1;0;2;AAA", "tc1;1;2;BBB"}); err != nil {
		t.Fatal(err)
	}
	// deSEC stores TXT values in presentation format (double-quoted).
	got := mock.rrsets["_tincan"]
	want := []string{`"tc1;0;2;AAA"`, `"tc1;1;2;BBB"`}
	if !equalStrings(got, want) {
		t.Fatalf("stored records = %v, want quoted %v", got, want)
	}

	// ListTXT round-trips back to the unquoted values.
	list, err := p.ListTXT(ctx, "example.com", "_tincan")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Value != "tc1;0;2;AAA" || list[1].Value != "tc1;1;2;BBB" {
		t.Fatalf("ListTXT = %+v, want the two unquoted values", list)
	}

	// A second replace fully supersedes the first (shrinks to one record).
	if err := r.ReplaceTXT(ctx, "example.com", "_tincan", []string{"tc1;0;1;ZZZ"}); err != nil {
		t.Fatal(err)
	}
	if got := mock.rrsets["_tincan"]; len(got) != 1 || got[0] != `"tc1;0;1;ZZZ"` {
		t.Fatalf("after replace, records = %v, want one quoted ZZZ", got)
	}

	// The unrelated RRset is untouched: the write is per-RRset, not zone-wide.
	if got := mock.rrsets["other"]; len(got) != 1 || got[0] != `"keep-me"` {
		t.Fatalf("unrelated RRset = %v, want it preserved", got)
	}
}

// TestDeSECPerRecordReconcile exercises the per-record Provider methods (the
// read-modify-write path, with subname-encoded ids) so the shared get/put
// machinery is fully covered even though the drop prefers ReplaceTXT.
func TestDeSECPerRecordReconcile(t *testing.T) {
	mock := newDesecMock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	p, err := New(Config{Name: "desec", Token: "tok", BaseURL: srv.URL})
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
}

func TestDeSECAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"Invalid token."}`))
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "desec", Token: "bad", BaseURL: srv.URL})
	if _, err := p.ListTXT(context.Background(), "example.com", "_tincan"); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestDeSECDomainNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Not found."}`))
	}))
	defer srv.Close()

	// A write to a nonexistent domain 404s on the PUT, which maps to ErrNotFound.
	p, _ := New(Config{Name: "desec", Token: "tok", BaseURL: srv.URL})
	if err := p.(Replacer).ReplaceTXT(context.Background(), "absent.example", "_tincan", []string{"x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
