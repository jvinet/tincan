package dnsprovider

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// r53Mock emulates the subset of the Route 53 API the provider uses:
// ListHostedZonesByName (zone resolution), ListResourceRecordSets, and
// ChangeResourceRecordSets (UPSERT/DELETE). RRsets are stored keyed by their
// fully-qualified name (no trailing dot), holding the quoted record strings
// exactly as Route 53 would. The list endpoint returns *every* stored RRset
// (with trailing-dot names, like Route 53) so the provider's client-side
// name+type filtering is exercised.
type r53Mock struct {
	domain string
	zoneID string
	rrsets map[string]r53RRSet
}

func newR53Mock() *r53Mock {
	return &r53Mock{domain: "example.com", zoneID: "Z-EXAMPLE", rrsets: map[string]r53RRSet{}}
}

func writeR53XML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_ = xml.NewEncoder(w).Encode(v)
}

func (m *r53Mock) handler() http.HandlerFunc {
	zonesByName := "/" + route53APIVersion + "/hostedzonesbyname"
	rrsetPath := "/" + route53APIVersion + "/hostedzone/" + m.zoneID + "/rrset"
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == zonesByName:
			var resp listHostedZonesByNameResponse
			if strings.EqualFold(strings.TrimSuffix(r.URL.Query().Get("dnsname"), "."), m.domain) {
				resp.HostedZones = []r53HostedZone{{ID: "/hostedzone/" + m.zoneID, Name: m.domain + "."}}
			}
			writeR53XML(w, http.StatusOK, resp)
		case r.Method == http.MethodGet && r.URL.Path == rrsetPath:
			var resp listResourceRecordSetsResponse
			for _, rr := range m.rrsets {
				resp.RRSets = append(resp.RRSets, rr)
			}
			writeR53XML(w, http.StatusOK, resp)
		case r.Method == http.MethodPost && r.URL.Path == rrsetPath+"/":
			var req struct {
				Changes []r53Change `xml:"ChangeBatch>Changes>Change"`
			}
			body, _ := io.ReadAll(r.Body)
			_ = xml.Unmarshal(body, &req)
			for _, c := range req.Changes {
				name := strings.TrimSuffix(c.ResourceRecordSet.Name, ".")
				switch c.Action {
				case "UPSERT":
					rr := c.ResourceRecordSet
					rr.Name = name + "." // store with a trailing dot, like Route 53
					m.rrsets[name] = rr
				case "DELETE":
					delete(m.rrsets, name)
				}
			}
			writeR53XML(w, http.StatusOK, struct {
				XMLName xml.Name `xml:"ChangeResourceRecordSetsResponse"`
			}{})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>NotFound</Code><Message>no route</Message></Error></ErrorResponse>`))
		}
	}
}

// TestRoute53ReplaceTXT covers the path the dns drop actually uses: a single
// atomic UPSERT of the whole RRset. It checks values are stored quoted, that a
// second replace fully supersedes the first, and that replacing one name leaves
// an unrelated RRset untouched (the write is scoped to one RRset, not the zone).
func TestRoute53ReplaceTXT(t *testing.T) {
	mock := newR53Mock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	p, err := New(Config{Name: "route53", AccessKey: "AKIA", SecretKey: "secret", TTL: 300, BaseURL: srv.URL})
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
	// Route 53 stores TXT values in presentation format (double-quoted).
	got := mock.rrsets["_tincan.example.com"].ResourceRecords
	if len(got) != 2 || got[0].Value != `"tc1;0;2;AAA"` || got[1].Value != `"tc1;1;2;BBB"` {
		t.Fatalf("stored records = %+v, want two quoted values", got)
	}

	// ListTXT round-trips back to the unquoted values, in order.
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
	if got := mock.rrsets["_tincan.example.com"].ResourceRecords; len(got) != 1 || got[0].Value != `"tc1;0;1;ZZZ"` {
		t.Fatalf("after replace, records = %+v, want one quoted ZZZ", got)
	}

	// The unrelated RRset is untouched: the write is per-RRset, not zone-wide.
	if got := mock.rrsets["other.example.com"].ResourceRecords; len(got) != 1 || got[0].Value != `"keep-me"` {
		t.Fatalf("unrelated RRset = %+v, want it preserved", got)
	}
}

// TestRoute53PerRecordReconcile exercises the per-record Provider methods (the
// read-modify-write path, with name-encoded ids) so the shared get/put/change
// machinery — including the DELETE-the-whole-RRset path when the last record is
// removed — is covered even though the drop prefers ReplaceTXT.
func TestRoute53PerRecordReconcile(t *testing.T) {
	mock := newR53Mock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	p, err := New(Config{Name: "route53", AccessKey: "AKIA", SecretKey: "secret", BaseURL: srv.URL})
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

	// Removing the final record deletes the RRset entirely (the DELETE path).
	if err := p.DeleteTXT(ctx, "example.com", list[0].ID); err != nil {
		t.Fatal(err)
	}
	list, err = p.ListTXT(ctx, "example.com", "_tincan")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("want 0 records after final delete, got %+v", list)
	}
	if _, ok := mock.rrsets["_tincan.example.com"]; ok {
		t.Fatal("RRset should be gone after its last record was deleted")
	}
}

func TestRoute53AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>bad creds</Message></Error></ErrorResponse>`))
	}))
	defer srv.Close()

	p, _ := New(Config{Name: "route53", AccessKey: "bad", SecretKey: "bad", BaseURL: srv.URL})
	if _, err := p.ListTXT(context.Background(), "example.com", "_tincan"); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestRoute53ZoneNotFound(t *testing.T) {
	mock := newR53Mock()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	// A write to a zone the account doesn't host: ListHostedZonesByName returns
	// no match, which the provider maps to ErrNotFound.
	p, _ := New(Config{Name: "route53", AccessKey: "AKIA", SecretKey: "secret", BaseURL: srv.URL})
	if err := p.(Replacer).ReplaceTXT(context.Background(), "absent.example", "_tincan", []string{"x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// TestAWSSignV4KnownAnswer pins the SigV4 signer to the official AWS test-suite
// "get-vanilla" vector (a plain GET, empty body, signing host;x-amz-date). The
// expected signature is the published value, independently reproduced from the
// AWS spec. This guards the canonicalization and the HMAC key-derivation chain.
func TestAWSSignV4KnownAnswer(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	awsSignV4(req, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "service", nil, when)

	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Fatalf("X-Amz-Date = %q, want 20150830T123600Z", got)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestAWSCanonicalQuery(t *testing.T) {
	cases := []struct {
		name string
		in   url.Values
		want string
	}{
		{"empty", url.Values{}, ""},
		{"sorted by key", url.Values{"type": {"TXT"}, "name": {"_tincan.example.com"}}, "name=_tincan.example.com&type=TXT"},
		{"already ordered", url.Values{"dnsname": {"example.com"}, "maxitems": {"1"}}, "dnsname=example.com&maxitems=1"},
		{"space as %20", url.Values{"q": {"a b"}}, "q=a%20b"},
		{"unreserved untouched", url.Values{"v": {"a-b_c.d~e"}}, "v=a-b_c.d~e"},
		{"reserved encoded", url.Values{"v": {"a/b=c"}}, "v=a%2Fb%3Dc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := awsCanonicalQuery(tc.in); got != tc.want {
				t.Fatalf("awsCanonicalQuery = %q, want %q", got, tc.want)
			}
		})
	}
}
