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

// cfMock emulates the subset of the Cloudflare API the provider uses: a zone
// lookup by name and TXT record CRUD under the resolved zone id. Records are
// stored with their fully-qualified name. The list handler deliberately ignores
// the ?name= filter and returns every TXT record, so the test exercises the
// provider's own client-side FQDN matching rather than the mock's.
type cfMock struct {
	records map[string]cfRecord // record id -> record
	nextID  int
	zone    string
	zoneID  string
}

func newCFMock() *cfMock {
	return &cfMock{records: map[string]cfRecord{}, nextID: 1000, zone: "example.com", zoneID: "zoneABC"}
}

func (m *cfMock) writeList(w http.ResponseWriter, result any) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"errors":      []any{},
		"result":      result,
		"result_info": map[string]any{"page": 1, "total_pages": 1},
	})
}

func (m *cfMock) writeObject(w http.ResponseWriter, result any) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"errors":  []any{},
		"result":  result,
	})
}

func (m *cfMock) handler() http.HandlerFunc {
	recordsPath := "/zones/" + m.zoneID + "/dns_records"
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			var zones []cfZone
			if strings.EqualFold(r.URL.Query().Get("name"), m.zone) {
				zones = append(zones, cfZone{ID: m.zoneID, Name: m.zone})
			}
			m.writeList(w, zones)
		case r.Method == http.MethodGet && r.URL.Path == recordsPath:
			typeFilter := r.URL.Query().Get("type")
			recs := make([]cfRecord, 0, len(m.records))
			for _, rec := range m.records {
				if typeFilter != "" && rec.Type != typeFilter {
					continue
				}
				recs = append(recs, rec)
			}
			m.writeList(w, recs)
		case r.Method == http.MethodPost && r.URL.Path == recordsPath:
			var rec cfRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			m.nextID++
			rec.ID = "rec" + strconv.Itoa(m.nextID)
			m.records[rec.ID] = rec
			m.writeObject(w, rec)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
			id := idFromPath(r.URL.Path)
			var body cfRecord
			_ = json.NewDecoder(r.Body).Decode(&body)
			rec := m.records[id]
			rec.Content = body.Content
			if body.TTL != 0 {
				rec.TTL = body.TTL
			}
			m.records[id] = rec
			m.writeObject(w, rec)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
			id := idFromPath(r.URL.Path)
			delete(m.records, id)
			m.writeObject(w, cfRecord{ID: id})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestCloudflareRoundTrip(t *testing.T) {
	mock := newCFMock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	p, err := New(Config{Name: "cloudflare", Token: "tok", TTL: 300, BaseURL: srv.URL})
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
	// scoped ListTXT. The mock ignores the name filter, so this exercises the
	// provider's own client-side FQDN matching.
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

func TestCloudflareAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A well-formed but unauthorized token: Cloudflare returns 403 with
		// error code 9109.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}]}`))
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "cloudflare", Token: "bad", BaseURL: srv.URL})
	if _, err := p.ListTXT(context.Background(), "example.com", "_tincan"); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestCloudflareZoneNotFound(t *testing.T) {
	// Cloudflare answers an unknown zone with 200 and an empty result array,
	// not a 404, so the provider must turn the empty match into ErrNotFound.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":     true,
			"errors":      []any{},
			"result":      []any{},
			"result_info": map[string]any{"page": 1, "total_pages": 1},
		})
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "cloudflare", Token: "tok", BaseURL: srv.URL})
	if err := p.CreateTXT(context.Background(), "absent.example", "_tincan", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}
