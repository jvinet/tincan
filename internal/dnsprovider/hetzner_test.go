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

// hetznerMock emulates the subset of the Hetzner DNS API the provider uses: a
// zone lookup by name and TXT record CRUD addressed by opaque record id. The
// list handler returns every record regardless of the zone_id filter, so the
// test exercises the provider's own client-side name matching rather than the
// mock's. Records store their relative host label, as Hetzner does.
type hetznerMock struct {
	records   map[string]hetznerRecord // record id -> record
	nextID    int
	zone      string
	zoneID    string
	zoneCalls int
}

func newHetznerMock() *hetznerMock {
	return &hetznerMock{records: map[string]hetznerRecord{}, nextID: 1000, zone: "example.com", zoneID: "zoneABC"}
}

func (m *hetznerMock) writeZones(w http.ResponseWriter, zones []hetznerZone) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"zones": zones,
		"meta":  map[string]any{"pagination": map[string]any{"page": 1, "last_page": 1}},
	})
}

func (m *hetznerMock) writeRecords(w http.ResponseWriter, recs []hetznerRecord) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"records": recs,
		"meta":    map[string]any{"pagination": map[string]any{"page": 1, "last_page": 1}},
	})
}

func (m *hetznerMock) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			m.zoneCalls++
			var zones []hetznerZone
			if strings.EqualFold(r.URL.Query().Get("name"), m.zone) {
				zones = append(zones, hetznerZone{ID: m.zoneID, Name: m.zone})
			}
			m.writeZones(w, zones)
		case r.Method == http.MethodGet && r.URL.Path == "/records":
			recs := make([]hetznerRecord, 0, len(m.records))
			for _, rec := range m.records {
				recs = append(recs, rec)
			}
			m.writeRecords(w, recs)
		case r.Method == http.MethodPost && r.URL.Path == "/records":
			var rec hetznerRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			m.nextID++
			rec.ID = "rec" + strconv.Itoa(m.nextID)
			m.records[rec.ID] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"record": rec})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/records/"):
			rec, ok := m.records[idFromPath(r.URL.Path)]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"record": rec})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/records/"):
			id := idFromPath(r.URL.Path)
			var body hetznerRecord
			_ = json.NewDecoder(r.Body).Decode(&body)
			rec := m.records[id]
			// Hetzner's PUT is a full replace; the provider resends name/type/
			// zone_id, so the value is what changes here.
			rec.Value = body.Value
			rec.Name = body.Name
			rec.Type = body.Type
			rec.ZoneID = body.ZoneID
			if body.TTL != 0 {
				rec.TTL = body.TTL
			}
			m.records[id] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"record": rec})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/records/"):
			delete(m.records, idFromPath(r.URL.Path))
			_ = json.NewEncoder(w).Encode(struct{}{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestHetznerRoundTrip(t *testing.T) {
	mock := newHetznerMock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	p, err := New(Config{Name: "hetzner", Token: "tok", TTL: 300, BaseURL: srv.URL})
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
	// scoped ListTXT. The mock returns every record, so this exercises the
	// provider's own client-side name matching.
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

	// The zone id should have been resolved once and cached across the create
	// and list operations above (UpdateTXT/DeleteTXT address records directly).
	if mock.zoneCalls != 1 {
		t.Fatalf("zone id resolved %d times, want 1 (cached)", mock.zoneCalls)
	}
}

func TestHetznerAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid authentication credentials"}`))
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "hetzner", Token: "bad", BaseURL: srv.URL})
	if _, err := p.ListTXT(context.Background(), "example.com", "_tincan"); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestHetznerZoneNotFound(t *testing.T) {
	// Hetzner answers an unknown zone name with 200 and an empty zones array, so
	// the provider must turn the empty match into ErrNotFound.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"zones": []any{},
			"meta":  map[string]any{"pagination": map[string]any{"page": 1, "last_page": 1}},
		})
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "hetzner", Token: "tok", BaseURL: srv.URL})
	if err := p.CreateTXT(context.Background(), "absent.example", "_tincan", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}
