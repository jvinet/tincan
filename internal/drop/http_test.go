package drop

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
)

func TestHTTPDrop(t *testing.T) {
	body := []byte("blob")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Content-Length", "4")
		w.Header().Set("Last-Modified", time.Unix(100, 0).UTC().Format(http.TimeFormat))
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write(body)
		case http.MethodHead:
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	d := NewHTTP(srv.URL, "", "")
	got, err := d.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %q", got)
	}
	meta, err := d.Stat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if meta.Size != 4 || meta.ETag != "abc" || !meta.UpdatedAt.Equal(time.Unix(100, 0).UTC()) {
		t.Fatalf("unexpected metadata: %+v", meta)
	}
	if err := d.Put(context.Background(), body); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("expected read-only error, got %v", err)
	}
}

func TestHTTPDropBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "bob" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := NewHTTP(srv.URL, "bob", "secret")
	got, err := d.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok" {
		t.Fatalf("got %q", got)
	}

	unauthenticated := NewHTTP(srv.URL, "", "")
	if _, err := unauthenticated.Get(context.Background()); !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth, got %v", err)
	}
}

func TestHTTPDropStatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{status: http.StatusNotFound, want: ErrNotFound},
		{status: http.StatusUnauthorized, want: ErrAuth},
		{status: http.StatusForbidden, want: ErrAuth},
		{status: http.StatusInternalServerError, want: nil},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			d := NewHTTP(srv.URL, "", "")
			_, err := d.Get(context.Background())
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("got %v want %v", err, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatal("expected generic HTTP status error")
			}
		})
	}
}

// A hostile drop streaming an unbounded body (chunked, no Content-Length)
// must be cut off at the blob cap instead of exhausting memory.
func TestHTTPDropRejectsOversizedObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, directory.MaxBlobSize+1))
	}))
	defer srv.Close()
	d := NewHTTP(srv.URL, "", "")
	if _, err := d.Get(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error, got %v", err)
	}
}

// When the server declares the oversize up front, the fetch must abort on
// the header without reading the body at all.
func TestHTTPDropRejectsDeclaredOversizedObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(directory.MaxBlobSize+1, 10))
		_, _ = w.Write(make([]byte, directory.MaxBlobSize+1))
	}))
	defer srv.Close()
	d := NewHTTP(srv.URL, "", "")
	if _, err := d.Get(context.Background()); err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatalf("expected size error, got %v", err)
	}
}
