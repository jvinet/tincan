package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultDeSECBaseURL = "https://desec.io/api/v1"
	// deSEC requires a TTL on every RRset write and rejects values below the
	// domain's minimum TTL, which defaults to 3600. Use that when the config
	// leaves ttl unset, so a publish doesn't fail for want of a TTL.
	defaultDeSECTTL = 3600
)

// deSEC implements Provider and Replacer against the deSEC DNS API:
// https://desec.readthedocs.io/en/latest/dns/rrsets.html
//
// deSEC differs from the other providers in a way that shapes this file: it has
// no individually-addressable records. The TXT records at a name form a single
// "resource record set" (RRset) — one object holding a `records` array — with
// no per-record id. So the natural operation is to replace the whole set in one
// atomic, create-or-update call, which is what ReplaceTXT does and what the dns
// drop uses for deSEC. The per-record Provider methods are still implemented
// (read-modify-write over the RRset, keyed on the record value) so deSEC is a
// complete Provider, but the drop prefers ReplaceTXT.
//
// Two further wrinkles:
//   - Authentication is "Authorization: Token <token>", not Bearer.
//   - TXT values are stored in DNS presentation format, i.e. enclosed in double
//     quotes; we add the quotes on write and strip them on read. tincan's chunk
//     values are base64url plus "tc1;<seq>;<total>;" — no quotes or backslashes
//     — so no further escaping is needed.
//
// Writes go to the single-RRset endpoint (PUT .../rrsets/<subname>/TXT/), which
// upserts only that one RRset. The bulk endpoint is deliberately avoided: its
// behavior toward RRsets absent from the payload is unspecified, and a wrong
// guess could delete the zone's other records.
type deSEC struct {
	token   string
	ttl     int
	baseURL string
	client  *http.Client
}

func newDeSEC(cfg Config) *deSEC {
	base := cfg.BaseURL
	if base == "" {
		base = defaultDeSECBaseURL
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultDeSECTTL
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &deSEC{token: cfg.Token, ttl: ttl, baseURL: base, client: hc}
}

type desecRRset struct {
	Subname string   `json:"subname"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

// ReplaceTXT publishes values as the complete TXT RRset at name in one atomic
// upsert. This is the path the dns drop uses for deSEC.
func (s *deSEC) ReplaceTXT(ctx context.Context, zone, name string, values []string) error {
	return s.putRecords(ctx, zone, name, values)
}

func (s *deSEC) ListTXT(ctx context.Context, zone, name string) ([]TXTRecord, error) {
	values, err := s.getRecords(ctx, zone, name)
	if err != nil {
		return nil, err
	}
	out := make([]TXTRecord, 0, len(values))
	for _, v := range values {
		out = append(out, TXTRecord{ID: desecID(name, v), Value: v})
	}
	return out, nil
}

func (s *deSEC) CreateTXT(ctx context.Context, zone, name, value string) error {
	values, err := s.getRecords(ctx, zone, name)
	if err != nil {
		return err
	}
	return s.putRecords(ctx, zone, name, append(values, value))
}

func (s *deSEC) UpdateTXT(ctx context.Context, zone, id, value string) error {
	name, old := splitDesecID(id)
	values, err := s.getRecords(ctx, zone, name)
	if err != nil {
		return err
	}
	for i, v := range values {
		if v == old {
			values[i] = value
			break
		}
	}
	return s.putRecords(ctx, zone, name, values)
}

func (s *deSEC) DeleteTXT(ctx context.Context, zone, id string) error {
	name, old := splitDesecID(id)
	values, err := s.getRecords(ctx, zone, name)
	if err != nil {
		return err
	}
	out := values[:0]
	for _, v := range values {
		if v != old {
			out = append(out, v)
		}
	}
	return s.putRecords(ctx, zone, name, out)
}

// getRecords returns the (unquoted) TXT values of the RRset at name. A 404 means
// the RRset does not exist yet — a normal first-publish state — and maps to an
// empty set rather than an error; a genuinely missing domain surfaces on the
// subsequent write (putRecords), which 404s as ErrNotFound.
func (s *deSEC) getRecords(ctx context.Context, zone, name string) ([]string, error) {
	status, data, err := s.do(ctx, http.MethodGet, s.rrsetURL(zone, name), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if err := statusError("desec", status, data, desecErrReason); err != nil {
		return nil, err
	}
	var rr desecRRset
	if err := json.Unmarshal(data, &rr); err != nil {
		return nil, fmt.Errorf("decode desec rrset: %w", err)
	}
	out := make([]string, 0, len(rr.Records))
	for _, r := range rr.Records {
		out = append(out, unquoteTXT(r))
	}
	return out, nil
}

// putRecords replaces the TXT RRset at name with values (quoting each for the
// API), creating the RRset if absent. An empty set deletes the RRset.
//
// deSEC's only guaranteed create primitive is POST to the rrsets collection;
// the single-RRset detail PUT modifies an existing RRset (and may or may not
// create a missing one, depending on endpoint semantics). So we PUT to replace
// and, on a 404 (no such RRset yet — the normal first-publish case), fall back
// to POST to create. A genuinely missing domain 404s on the POST too and
// surfaces as ErrNotFound. This is correct whether or not detail PUT creates.
func (s *deSEC) putRecords(ctx context.Context, zone, name string, values []string) error {
	if len(values) == 0 {
		return s.deleteRRset(ctx, zone, name)
	}
	records := make([]string, len(values))
	for i, v := range values {
		records[i] = `"` + v + `"` // presentation format; values are quote/backslash-free
	}
	body := desecRRset{Subname: bodySubname(name), Type: "TXT", TTL: s.ttl, Records: records}
	status, data, err := s.do(ctx, http.MethodPut, s.rrsetURL(zone, name), body)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		status, data, err = s.do(ctx, http.MethodPost, s.rrsetsURL(zone), body)
		if err != nil {
			return err
		}
	}
	return statusError("desec", status, data, desecErrReason)
}

func (s *deSEC) deleteRRset(ctx context.Context, zone, name string) error {
	status, data, err := s.do(ctx, http.MethodDelete, s.rrsetURL(zone, name), nil)
	if err != nil {
		return err
	}
	return statusError("desec", status, data, desecErrReason)
}

// rrsetURL builds the single-RRset (detail) endpoint for the TXT records at
// name; rrsetsURL builds the collection endpoint used to create a new RRset.
func (s *deSEC) rrsetURL(zone, name string) string {
	return fmt.Sprintf("%s/domains/%s/rrsets/%s/TXT/", s.baseURL, zone, urlSubname(name))
}

func (s *deSEC) rrsetsURL(zone string) string {
	return fmt.Sprintf("%s/domains/%s/rrsets/", s.baseURL, zone)
}

// do issues the request and returns the status and body without mapping it to a
// sentinel error, so callers (getRecords) can treat 404 specially.
func (s *deSEC) do(ctx context.Context, method, reqURL string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("marshal desec request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("create desec request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+s.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("desec API request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("read desec response: %w", err)
	}
	return resp.StatusCode, data, nil
}

// urlSubname is the host label as it appears in the RRset URL path; the zone
// apex uses the placeholder "@".
func urlSubname(name string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "" || name == "@" {
		return "@"
	}
	return name
}

// bodySubname is the host label as it appears in an RRset request body; the
// zone apex is the empty string.
func bodySubname(name string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "@" {
		return ""
	}
	return name
}

// desecID encodes the subname alongside the record value. The per-record
// mutators (UpdateTXT/DeleteTXT) receive only this opaque id, not the name, so
// the name has to travel with it to locate the right RRset for the
// read-modify-write. "/" is a safe separator: it appears in neither DNS
// subnames nor tincan's base64url chunk values.
func desecID(name, value string) string { return name + "/" + value }

func splitDesecID(id string) (name, value string) {
	if before, after, found := strings.Cut(id, "/"); found {
		return before, after
	}
	return "", id
}

// unquoteTXT strips the surrounding double quotes deSEC stores TXT values with.
// tincan writes single-string values under 255 bytes, so a single quote pair is
// all there is to remove.
func unquoteTXT(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// desecErrReason extracts the human-readable message from a deSEC error body,
// which for auth and not-found errors is {"detail":"..."}.
func desecErrReason(body []byte) string {
	var e struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &e) == nil && e.Detail != "" {
		return e.Detail
	}
	if len(body) > 0 {
		return string(body)
	}
	return "(no body)"
}
