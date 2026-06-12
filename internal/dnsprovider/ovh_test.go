package dnsprovider

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	ovhTestAppKey      = "ak"
	ovhTestAppSecret   = "as"
	ovhTestConsumerKey = "ck"
)

// ovhMock emulates the subset of the OVH API the provider uses, including the
// idiosyncrasies that make OVH unlike the token providers: list returns only
// record ids, and writes must be committed with a zone refresh. Crucially it
// re-derives and checks the X-Ovh-Signature on every authenticated call, so a
// passing round-trip proves the request-signing implementation is correct.
type ovhMock struct {
	records   map[int64]ovhRecord
	nextID    int64
	refreshes int
}

func newOVHMock() *ovhMock {
	return &ovhMock{records: map[int64]ovhRecord{}, nextID: 1000}
}

func ovhSign(method, fullURL, body, ts string) string {
	h := sha1.New()
	h.Write([]byte(ovhTestAppSecret + "+" + ovhTestConsumerKey + "+" + method + "+" + fullURL + "+" + body + "+" + ts))
	return "$1$" + hex.EncodeToString(h.Sum(nil))
}

func (m *ovhMock) handler() http.HandlerFunc {
	const recordsPath = "/domain/zone/example.com/record"
	return func(w http.ResponseWriter, r *http.Request) {
		// /auth/time is unauthenticated; answer it before signature checks.
		if r.URL.Path == "/auth/time" {
			fmt.Fprintf(w, "%d", time.Now().Unix())
			return
		}
		body, _ := io.ReadAll(r.Body)

		// Verify the signature exactly as the server would: reconstruct the
		// full URL the client signed from the received request.
		fullURL := "http://" + r.Host + r.URL.RequestURI()
		want := ovhSign(r.Method, fullURL, string(body), r.Header.Get("X-Ovh-Timestamp"))
		if r.Header.Get("X-Ovh-Application") != ovhTestAppKey ||
			r.Header.Get("X-Ovh-Consumer") != ovhTestConsumerKey ||
			r.Header.Get("X-Ovh-Signature") != want {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Invalid signature"}`))
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == recordsPath:
			fieldType := r.URL.Query().Get("fieldType")
			subDomain := r.URL.Query().Get("subDomain")
			ids := make([]int64, 0, len(m.records))
			for id, rec := range m.records {
				if fieldType != "" && rec.FieldType != fieldType {
					continue
				}
				if rec.SubDomain != subDomain {
					continue
				}
				ids = append(ids, id)
			}
			_ = json.NewEncoder(w).Encode(ids)
		case r.Method == http.MethodPost && r.URL.Path == recordsPath:
			var rec ovhRecord
			_ = json.Unmarshal(body, &rec)
			m.nextID++
			rec.ID = m.nextID
			m.records[rec.ID] = rec
			_ = json.NewEncoder(w).Encode(rec)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
			id, _ := strconv.ParseInt(idFromPath(r.URL.Path), 10, 64)
			rec, ok := m.records[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(rec)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
			id, _ := strconv.ParseInt(idFromPath(r.URL.Path), 10, 64)
			var in ovhRecord
			_ = json.Unmarshal(body, &in)
			rec := m.records[id]
			rec.Target = in.Target
			if in.TTL != 0 {
				rec.TTL = in.TTL
			}
			m.records[id] = rec
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
			id, _ := strconv.ParseInt(idFromPath(r.URL.Path), 10, 64)
			delete(m.records, id)
		case r.Method == http.MethodPost && r.URL.Path == "/domain/zone/example.com/refresh":
			m.refreshes++
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestOVHRoundTrip(t *testing.T) {
	mock := newOVHMock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	p, err := New(Config{
		Name: "ovh", AppKey: ovhTestAppKey, AppSecret: ovhTestAppSecret,
		ConsumerKey: ovhTestConsumerKey, TTL: 300, BaseURL: srv.URL,
	})
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
	// A record at a different subdomain must not appear in a scoped list.
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

	// Record edits stage in the zone; only Flush (the refresh) commits them.
	// The provider must implement Flusher and the CRUD calls must not refresh
	// on their own.
	if mock.refreshes != 0 {
		t.Fatalf("CRUD calls triggered %d refreshes, want 0 (refresh is Flush's job)", mock.refreshes)
	}
	f, ok := p.(Flusher)
	if !ok {
		t.Fatal("ovh provider must implement Flusher")
	}
	if err := f.Flush(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if mock.refreshes != 1 {
		t.Fatalf("Flush triggered %d refreshes, want 1", mock.refreshes)
	}
}

func TestOVHAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/time" {
			fmt.Fprintf(w, "%d", time.Now().Unix())
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p, err := New(Config{Name: "ovh", AppKey: "ak", AppSecret: "as", ConsumerKey: "bad", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ListTXT(context.Background(), "example.com", "_tincan"); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestOVHEndpointResolution(t *testing.T) {
	if _, err := New(Config{Name: "ovh", Endpoint: "does-not-exist"}); err == nil {
		t.Fatal("expected error for unknown ovh endpoint")
	}
	// An empty endpoint defaults to ovh-eu and resolves without error.
	if _, err := New(Config{Name: "ovh"}); err != nil {
		t.Fatalf("default endpoint should resolve: %v", err)
	}
}
