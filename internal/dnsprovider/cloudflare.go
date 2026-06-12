package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultCloudflareBaseURL = "https://api.cloudflare.com/client/v4"

// cloudflare implements Provider against the Cloudflare DNS API:
// https://developers.cloudflare.com/api/resources/dns/subresources/records/
//
// Cloudflare combines the two shapes already present in this package:
//
//   - Like Linode, a zone is addressed by an opaque id rather than its domain
//     name, so the name is resolved to a zone id once and cached.
//   - Like DigitalOcean, records carry their fully-qualified name
//     ("_tincan.example.com"); we build the FQDN for the list filter and for
//     create, and match returned records on it.
//
// Authentication is a single API token sent as a bearer credential, as with the
// other token providers; the token needs Zone:Read and DNS:Edit on the zone.
// Every response is wrapped in Cloudflare's uniform {success, errors, result,
// result_info} envelope, decoded by cfEnvelope.
type cloudflare struct {
	token   string
	ttl     int
	baseURL string
	client  *http.Client

	mu     sync.Mutex
	zoneID string // cached zone -> Cloudflare zone id; "" until resolved
}

func newCloudflare(cfg Config) *cloudflare {
	base := cfg.BaseURL
	if base == "" {
		base = defaultCloudflareBaseURL
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &cloudflare{token: cfg.Token, ttl: cfg.TTL, baseURL: base, client: hc}
}

// cfEnvelope is Cloudflare's uniform response wrapper. result is held as raw
// JSON so a single decode handles both the array shape (list/zones) and the
// object shape (create/update); callers unmarshal it into the type they expect.
type cfEnvelope struct {
	Success    bool            `json:"success"`
	Errors     []cfError       `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo cfResultInfo    `json:"result_info"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

func (c *cloudflare) ListTXT(ctx context.Context, zone, name string) ([]TXTRecord, error) {
	id, err := c.resolveZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	fqdn := cfFQDN(name, zone)
	var out []TXTRecord
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("type", "TXT")
		q.Set("name", fqdn)
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		reqURL := fmt.Sprintf("%s/zones/%s/dns_records?%s", c.baseURL, id, q.Encode())
		data, err := c.do(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		var env cfEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, fmt.Errorf("decode cloudflare records: %w", err)
		}
		var records []cfRecord
		if err := json.Unmarshal(env.Result, &records); err != nil {
			return nil, fmt.Errorf("decode cloudflare records: %w", err)
		}
		for _, r := range records {
			// Belt-and-suspenders: filter client-side too. Cloudflare's name
			// filter has changed form over time (a flat name= versus the newer
			// name.exact=), so don't rely on the server having scoped the list.
			// DNS names are case-insensitive.
			if r.Type == "TXT" && strings.EqualFold(r.Name, fqdn) {
				out = append(out, TXTRecord{ID: r.ID, Value: r.Content})
			}
		}
		if page >= env.ResultInfo.TotalPages || len(records) == 0 {
			break
		}
	}
	return out, nil
}

func (c *cloudflare) CreateTXT(ctx context.Context, zone, name, value string) error {
	id, err := c.resolveZoneID(ctx, zone)
	if err != nil {
		return err
	}
	body := c.recordBody(value)
	body["type"] = "TXT"
	body["name"] = cfFQDN(name, zone)
	_, err = c.do(ctx, http.MethodPost, fmt.Sprintf("%s/zones/%s/dns_records", c.baseURL, id), body)
	return err
}

func (c *cloudflare) UpdateTXT(ctx context.Context, zone, recordID, value string) error {
	id, err := c.resolveZoneID(ctx, zone)
	if err != nil {
		return err
	}
	// PATCH is a partial update: sending content (and optionally ttl) leaves the
	// record's name and type untouched. PUT would require resending both.
	_, err = c.do(ctx, http.MethodPatch, fmt.Sprintf("%s/zones/%s/dns_records/%s", c.baseURL, id, recordID), c.recordBody(value))
	return err
}

func (c *cloudflare) DeleteTXT(ctx context.Context, zone, recordID string) error {
	id, err := c.resolveZoneID(ctx, zone)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, fmt.Sprintf("%s/zones/%s/dns_records/%s", c.baseURL, id, recordID), nil)
	return err
}

func (c *cloudflare) recordBody(value string) map[string]any {
	body := map[string]any{"content": value}
	if c.ttl > 0 {
		body["ttl"] = c.ttl
	}
	return body
}

// resolveZoneID maps a zone name to Cloudflare's opaque zone id, caching the
// result so a publish that touches many records issues a single /zones call.
// Cloudflare answers an unknown zone with 200 and an empty result (not 404), so
// an empty match becomes ErrNotFound here.
func (c *cloudflare) resolveZoneID(ctx context.Context, zone string) (string, error) {
	c.mu.Lock()
	cached := c.zoneID
	c.mu.Unlock()
	if cached != "" {
		return cached, nil
	}
	q := url.Values{}
	q.Set("name", zone)
	data, err := c.do(ctx, http.MethodGet, c.baseURL+"/zones?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	var env cfEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return "", fmt.Errorf("decode cloudflare zones: %w", err)
	}
	var zones []cfZone
	if err := json.Unmarshal(env.Result, &zones); err != nil {
		return "", fmt.Errorf("decode cloudflare zones: %w", err)
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, zone) {
			c.mu.Lock()
			c.zoneID = z.ID
			c.mu.Unlock()
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: zone %q not found: %w", zone, ErrNotFound)
}

func (c *cloudflare) do(ctx context.Context, method, reqURL string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal cloudflare request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, rdr)
	if err != nil {
		return nil, fmt.Errorf("create cloudflare request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare API request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read cloudflare response: %w", err)
	}
	if err := statusError("cloudflare", resp.StatusCode, data, cloudflareErrReason); err != nil {
		return nil, err
	}
	return data, nil
}

// cfFQDN builds the fully-qualified name Cloudflare stores and filters on. An
// empty or "@" label targets the zone apex, whose record name is the bare zone.
func cfFQDN(name, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	name = strings.TrimSuffix(name, ".")
	if name == "" || name == "@" {
		return zone
	}
	return name + "." + zone
}

// cloudflareErrReason extracts the human-readable message(s) from a Cloudflare
// error body of the form {"success":false,"errors":[{"code":...,"message":...}]}.
func cloudflareErrReason(body []byte) string {
	var e struct {
		Errors []cfError `json:"errors"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		reasons := make([]string, 0, len(e.Errors))
		for _, er := range e.Errors {
			if er.Code != 0 {
				reasons = append(reasons, fmt.Sprintf("%d: %s", er.Code, er.Message))
			} else {
				reasons = append(reasons, er.Message)
			}
		}
		return strings.Join(reasons, "; ")
	}
	if len(body) > 0 {
		return string(body)
	}
	return "(no body)"
}
