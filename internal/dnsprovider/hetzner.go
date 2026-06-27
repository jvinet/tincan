package dnsprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const defaultHetznerBaseURL = "https://dns.hetzner.com/api/v1"

// hetzner implements Provider against the Hetzner DNS Console API:
// https://dns.hetzner.com/api-docs
//
// It combines the two shapes already present in this package:
//
//   - Like Cloudflare, a zone is addressed by an opaque id rather than its
//     domain name, so the name is resolved to a zone id once and cached.
//   - Like DigitalOcean, records carry their relative host label ("_tincan", or
//     "@" for the zone apex), so we create and match on the relative name.
//
// Two Hetzner quirks shape the code below:
//
//   - Authentication is a single API token sent in the Auth-API-Token header
//     (not a bearer Authorization header like the other token providers).
//   - A record write is a full PUT — it requires the record's name, type, and
//     zone_id alongside the new value, with no partial-update form. Since
//     Provider.UpdateTXT is handed only the record id and the new value,
//     UpdateTXT fetches the record first and carries those fields through.
type hetzner struct {
	token   string
	ttl     int
	baseURL string
	client  *http.Client

	mu     sync.Mutex
	zoneID string // cached zone -> Hetzner zone id; "" until resolved
}

func newHetzner(cfg Config) *hetzner {
	base := cfg.BaseURL
	if base == "" {
		base = defaultHetznerBaseURL
	}
	return &hetzner{token: cfg.Token, ttl: cfg.TTL, baseURL: base, client: defaultHTTPClient(cfg)}
}

type hetznerZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type hetznerRecord struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	ZoneID string `json:"zone_id"`
	TTL    int    `json:"ttl,omitempty"`
}

// hetznerMeta carries the pagination block both list endpoints return. last_page
// is 0 when absent, which the paging loops treat as "single page".
type hetznerMeta struct {
	Pagination struct {
		Page     int `json:"page"`
		LastPage int `json:"last_page"`
	} `json:"pagination"`
}

type hetznerZonesResponse struct {
	Zones []hetznerZone `json:"zones"`
	Meta  hetznerMeta   `json:"meta"`
}

type hetznerRecordsResponse struct {
	Records []hetznerRecord `json:"records"`
	Meta    hetznerMeta     `json:"meta"`
}

type hetznerRecordResponse struct {
	Record hetznerRecord `json:"record"`
}

func (h *hetzner) ListTXT(ctx context.Context, zone, name string) ([]TXTRecord, error) {
	zoneID, err := h.resolveZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	rel := hetznerRelName(name)
	var out []TXTRecord
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("zone_id", zoneID)
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		data, err := h.do(ctx, http.MethodGet, h.baseURL+"/records?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var resp hetznerRecordsResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("decode hetzner records: %w", err)
		}
		for _, r := range resp.Records {
			// Hetzner has no server-side name filter on /records, so scope to our
			// label here. It returns the relative host label, and DNS names are
			// case-insensitive.
			if r.Type == "TXT" && strings.EqualFold(r.Name, rel) {
				out = append(out, TXTRecord{ID: r.ID, Value: r.Value})
			}
		}
		// Stop on the last page, on an empty page, or when no pagination block was
		// returned (last_page 0).
		if last := resp.Meta.Pagination.LastPage; len(resp.Records) == 0 || last <= page {
			break
		}
	}
	return out, nil
}

func (h *hetzner) CreateTXT(ctx context.Context, zone, name, value string) error {
	zoneID, err := h.resolveZoneID(ctx, zone)
	if err != nil {
		return err
	}
	body := map[string]any{
		"zone_id": zoneID,
		"type":    "TXT",
		"name":    hetznerRelName(name),
		"value":   value,
	}
	if h.ttl > 0 {
		body["ttl"] = h.ttl
	}
	_, err = h.do(ctx, http.MethodPost, h.baseURL+"/records", body)
	return err
}

func (h *hetzner) UpdateTXT(ctx context.Context, _, recordID, value string) error {
	// A Hetzner PUT replaces the whole record, so it must resend the name, type,
	// and zone_id. Fetch the record to carry those through unchanged; the record
	// already knows its zone, so the zone argument is unused here.
	rec, err := h.getRecord(ctx, recordID)
	if err != nil {
		return err
	}
	body := map[string]any{
		"zone_id": rec.ZoneID,
		"type":    rec.Type,
		"name":    rec.Name,
		"value":   value,
	}
	if h.ttl > 0 {
		body["ttl"] = h.ttl
	}
	_, err = h.do(ctx, http.MethodPut, fmt.Sprintf("%s/records/%s", h.baseURL, recordID), body)
	return err
}

func (h *hetzner) DeleteTXT(ctx context.Context, _, recordID string) error {
	_, err := h.do(ctx, http.MethodDelete, fmt.Sprintf("%s/records/%s", h.baseURL, recordID), nil)
	return err
}

func (h *hetzner) getRecord(ctx context.Context, recordID string) (hetznerRecord, error) {
	data, err := h.do(ctx, http.MethodGet, fmt.Sprintf("%s/records/%s", h.baseURL, recordID), nil)
	if err != nil {
		return hetznerRecord{}, err
	}
	var resp hetznerRecordResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return hetznerRecord{}, fmt.Errorf("decode hetzner record: %w", err)
	}
	return resp.Record, nil
}

// resolveZoneID maps a zone name to Hetzner's opaque zone id, caching the result
// so a publish that touches many records issues a single /zones call. Hetzner
// answers an unknown zone name with a 200 and an empty list (or a 404 the do()
// helper maps to ErrNotFound), so an empty match becomes ErrNotFound here.
func (h *hetzner) resolveZoneID(ctx context.Context, zone string) (string, error) {
	h.mu.Lock()
	cached := h.zoneID
	h.mu.Unlock()
	if cached != "" {
		return cached, nil
	}
	q := url.Values{}
	q.Set("name", zone)
	data, err := h.do(ctx, http.MethodGet, h.baseURL+"/zones?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	var resp hetznerZonesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("decode hetzner zones: %w", err)
	}
	// Match client-side too: the ?name= filter does a prefix/substring search on
	// some Hetzner deployments, so don't trust it to have returned exactly one.
	for _, z := range resp.Zones {
		if strings.EqualFold(z.Name, zone) {
			h.mu.Lock()
			h.zoneID = z.ID
			h.mu.Unlock()
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("hetzner: zone %q not found: %w", zone, ErrNotFound)
}

func (h *hetzner) do(ctx context.Context, method, reqURL string, body any) ([]byte, error) {
	return doJSON(ctx, h.client, "hetzner", method, reqURL, body, func(req *http.Request) {
		req.Header.Set("Auth-API-Token", h.token)
	}, hetznerErrReason)
}

// hetznerRelName maps the drop's record label to Hetzner's relative host form:
// an empty or "@" label is the zone apex, which Hetzner denotes "@".
func hetznerRelName(name string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "" || name == "@" {
		return "@"
	}
	return name
}

// hetznerErrReason extracts the human-readable message from a Hetzner error
// body, which is either {"error":{"message":...,"code":...}} (most failures) or
// {"message":...} (authentication).
func hetznerErrReason(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil {
		switch {
		case e.Error.Message != "" && e.Error.Code != 0:
			return fmt.Sprintf("%d: %s", e.Error.Code, e.Error.Message)
		case e.Error.Message != "":
			return e.Error.Message
		case e.Message != "":
			return e.Message
		}
	}
	if len(body) > 0 {
		return string(body)
	}
	return "(no body)"
}
