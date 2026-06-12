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
	"time"
)

const defaultDigitalOceanBaseURL = "https://api.digitalocean.com/v2"

// digitalOcean implements Provider against the DigitalOcean DNS API:
// https://docs.digitalocean.com/reference/api/reference/#tag/Domain-Records
//
// Two differences from the Linode provider shape the code below:
//
//   - A zone is addressed by its domain name directly in the URL path
//     (/v2/domains/<zone>/records), so there is no numeric domain-id to resolve
//     or cache — every method is stateless.
//   - The list endpoint's ?name= filter matches the *fully-qualified* record
//     name ("_tincan.example.com"), while records are created and returned with
//     the *relative* host label ("_tincan", or "@" for the zone apex). We build
//     the FQDN for the query but compare and create with the relative label.
type digitalOcean struct {
	token   string
	ttl     int
	baseURL string
	client  *http.Client
}

func newDigitalOcean(cfg Config) *digitalOcean {
	base := cfg.BaseURL
	if base == "" {
		base = defaultDigitalOceanBaseURL
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &digitalOcean{token: cfg.Token, ttl: cfg.TTL, baseURL: base, client: hc}
}

type doRecord struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl,omitempty"`
}

type doRecordsResponse struct {
	DomainRecords []doRecord `json:"domain_records"`
	Links         struct {
		Pages struct {
			Next string `json:"next"`
		} `json:"pages"`
	} `json:"links"`
}

func (d *digitalOcean) ListTXT(ctx context.Context, zone, name string) ([]TXTRecord, error) {
	rel := doRelName(name)
	var out []TXTRecord
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("type", "TXT")
		q.Set("name", doFQDN(rel, zone))
		q.Set("per_page", "200")
		q.Set("page", strconv.Itoa(page))
		reqURL := fmt.Sprintf("%s/domains/%s/records?%s", d.baseURL, zone, q.Encode())
		data, err := d.do(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		var resp doRecordsResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("decode digitalocean records: %w", err)
		}
		for _, r := range resp.DomainRecords {
			// Belt-and-suspenders: filter client-side too, in case the provider
			// ignores ?name=. DigitalOcean returns the relative host label, and
			// DNS names are case-insensitive.
			if r.Type == "TXT" && strings.EqualFold(r.Name, rel) {
				out = append(out, TXTRecord{ID: strconv.FormatInt(r.ID, 10), Value: r.Data})
			}
		}
		if resp.Links.Pages.Next == "" || len(resp.DomainRecords) == 0 {
			break
		}
	}
	return out, nil
}

func (d *digitalOcean) CreateTXT(ctx context.Context, zone, name, value string) error {
	body := d.recordBody(value)
	body["type"] = "TXT"
	body["name"] = doRelName(name)
	_, err := d.do(ctx, http.MethodPost, fmt.Sprintf("%s/domains/%s/records", d.baseURL, zone), body)
	return err
}

func (d *digitalOcean) UpdateTXT(ctx context.Context, zone, recordID, value string) error {
	// PUT is a partial update: sending data (and optionally ttl) leaves the
	// record's name untouched. type is included because the API requires it.
	body := d.recordBody(value)
	body["type"] = "TXT"
	_, err := d.do(ctx, http.MethodPut, fmt.Sprintf("%s/domains/%s/records/%s", d.baseURL, zone, recordID), body)
	return err
}

func (d *digitalOcean) DeleteTXT(ctx context.Context, zone, recordID string) error {
	_, err := d.do(ctx, http.MethodDelete, fmt.Sprintf("%s/domains/%s/records/%s", d.baseURL, zone, recordID), nil)
	return err
}

func (d *digitalOcean) recordBody(value string) map[string]any {
	body := map[string]any{"data": value}
	if d.ttl > 0 {
		body["ttl"] = d.ttl
	}
	return body
}

// doRelName maps the drop's record label to DigitalOcean's relative host form:
// an empty label is the zone apex, which DigitalOcean denotes "@".
func doRelName(name string) string {
	if name == "" {
		return "@"
	}
	return name
}

// doFQDN builds the fully-qualified name the list endpoint's ?name= filter
// expects. The apex ("@") filters on the bare zone.
func doFQDN(rel, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if rel == "@" {
		return zone
	}
	return rel + "." + zone
}

func (d *digitalOcean) do(ctx context.Context, method, reqURL string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal digitalocean request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, rdr)
	if err != nil {
		return nil, fmt.Errorf("create digitalocean request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("digitalocean API request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read digitalocean response: %w", err)
	}
	if err := statusError("digitalocean", resp.StatusCode, data, doErrReason); err != nil {
		return nil, err
	}
	return data, nil
}

// doErrReason extracts the human-readable message from a DigitalOcean error
// response body of the form {"id":"...","message":"..."}.
func doErrReason(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		return e.Message
	}
	if len(body) > 0 {
		return string(body)
	}
	return "(no body)"
}
