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

// doMock emulates the subset of the DigitalOcean API the provider uses. It
// stores records under their relative host label and applies the ?name= filter
// against the fully-qualified name, exactly as the real API does — so the test
// exercises the provider's FQDN construction and relative-name matching.
type doMock struct {
	records map[int64]doRecord
	nextID  int64
	zone    string
}

func newDOMock() *doMock {
	return &doMock{records: map[int64]doRecord{}, nextID: 1000, zone: "example.com"}
}

func (m *doMock) fqdn(rel string) string {
	if rel == "@" {
		return m.zone
	}
	return rel + "." + m.zone
}

func (m *doMock) handler() http.HandlerFunc {
	recordsPath := "/domains/" + m.zone + "/records"
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == recordsPath:
			nameFilter := r.URL.Query().Get("name")
			typeFilter := r.URL.Query().Get("type")
			data := make([]doRecord, 0, len(m.records))
			for _, rec := range m.records {
				if typeFilter != "" && rec.Type != typeFilter {
					continue
				}
				if nameFilter != "" && !strings.EqualFold(nameFilter, m.fqdn(rec.Name)) {
					continue
				}
				data = append(data, rec)
			}
			_ = json.NewEncoder(w).Encode(doRecordsResponse{DomainRecords: data})
		case r.Method == http.MethodPost && r.URL.Path == recordsPath:
			var rec doRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			m.nextID++
			rec.ID = m.nextID
			m.records[rec.ID] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"domain_record": rec})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
			id, _ := strconv.ParseInt(idFromPath(r.URL.Path), 10, 64)
			var body doRecord
			_ = json.NewDecoder(r.Body).Decode(&body)
			rec := m.records[id]
			rec.Data = body.Data
			if body.TTL != 0 {
				rec.TTL = body.TTL
			}
			m.records[id] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"domain_record": rec})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
			id, _ := strconv.ParseInt(idFromPath(r.URL.Path), 10, 64)
			delete(m.records, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestDigitalOceanRoundTrip(t *testing.T) {
	mock := newDOMock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	p, err := New(Config{Name: "digitalocean", Token: "tok", TTL: 1800, BaseURL: srv.URL})
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
	// An unrelated TXT record at a different name must not be returned by a
	// scoped ListTXT (validates the ?name= FQDN filter).
	if err := p.CreateTXT(ctx, "example.com", "other", "unrelated"); err != nil {
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

func TestDigitalOceanAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "digitalocean", Token: "bad", BaseURL: srv.URL})
	if _, err := p.ListTXT(context.Background(), "example.com", "_tincan"); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestDigitalOceanDomainNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"id":"not_found","message":"The resource you requested could not be found."}`))
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "digitalocean", Token: "tok", BaseURL: srv.URL})
	if err := p.CreateTXT(context.Background(), "absent.example", "_tincan", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}
