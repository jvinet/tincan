package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultLinodeBaseURL = "https://api.linode.com/v4"

// linode implements Provider against the Linode (Akamai) DNS API:
// https://techdocs.akamai.com/linode-api/reference/post-domain-record
type linode struct {
	token   string
	ttl     int
	baseURL string
	client  *http.Client

	mu       sync.Mutex
	domainID int64 // cached zone -> Linode domain id; 0 until resolved
}

func newLinode(cfg Config) *linode {
	base := cfg.BaseURL
	if base == "" {
		base = defaultLinodeBaseURL
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &linode{token: cfg.Token, ttl: cfg.TTL, baseURL: base, client: hc}
}

type linodeDomain struct {
	ID     int64  `json:"id"`
	Domain string `json:"domain"`
}

type linodeRecord struct {
	ID     int64  `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Target string `json:"target"`
	TTLSec int    `json:"ttl_sec,omitempty"`
}

type domainsResponse struct {
	Data  []linodeDomain `json:"data"`
	Pages int            `json:"pages"`
}

type recordsResponse struct {
	Data  []linodeRecord `json:"data"`
	Pages int            `json:"pages"`
}

func (l *linode) ListTXT(ctx context.Context, zone, name string) ([]TXTRecord, error) {
	id, err := l.resolveDomainID(ctx, zone)
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf(`{"type": "TXT", "name": %q}`, name)
	var out []TXTRecord
	for page := 1; ; page++ {
		url := fmt.Sprintf("%s/domains/%d/records?page=%d&page_size=500", l.baseURL, id, page)
		data, err := l.do(ctx, http.MethodGet, url, filter, nil)
		if err != nil {
			return nil, err
		}
		var resp recordsResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("decode linode records: %w", err)
		}
		for _, r := range resp.Data {
			// Belt-and-suspenders: filter client-side too, in case the
			// provider ignores X-Filter. DNS names are case-insensitive, so
			// match without regard to case (the provider may have normalized).
			if r.Type == "TXT" && strings.EqualFold(r.Name, name) {
				out = append(out, TXTRecord{ID: strconv.FormatInt(r.ID, 10), Value: r.Target})
			}
		}
		if page >= resp.Pages || len(resp.Data) == 0 {
			break
		}
	}
	return out, nil
}

func (l *linode) CreateTXT(ctx context.Context, zone, name, value string) error {
	id, err := l.resolveDomainID(ctx, zone)
	if err != nil {
		return err
	}
	body := l.recordBody(value)
	body["type"] = "TXT"
	body["name"] = name
	_, err = l.do(ctx, http.MethodPost, fmt.Sprintf("%s/domains/%d/records", l.baseURL, id), "", body)
	return err
}

func (l *linode) UpdateTXT(ctx context.Context, zone, recordID, value string) error {
	id, err := l.resolveDomainID(ctx, zone)
	if err != nil {
		return err
	}
	_, err = l.do(ctx, http.MethodPut, fmt.Sprintf("%s/domains/%d/records/%s", l.baseURL, id, recordID), "", l.recordBody(value))
	return err
}

func (l *linode) DeleteTXT(ctx context.Context, zone, recordID string) error {
	id, err := l.resolveDomainID(ctx, zone)
	if err != nil {
		return err
	}
	_, err = l.do(ctx, http.MethodDelete, fmt.Sprintf("%s/domains/%d/records/%s", l.baseURL, id, recordID), "", nil)
	return err
}

func (l *linode) recordBody(value string) map[string]any {
	body := map[string]any{"target": value}
	if l.ttl > 0 {
		body["ttl_sec"] = l.ttl
	}
	return body
}

// resolveDomainID maps a zone name to Linode's numeric domain id, caching the
// result so a publish that touches many records issues a single /domains call.
func (l *linode) resolveDomainID(ctx context.Context, zone string) (int64, error) {
	l.mu.Lock()
	cached := l.domainID
	l.mu.Unlock()
	if cached != 0 {
		return cached, nil
	}
	filter := fmt.Sprintf(`{"domain": %q}`, zone)
	data, err := l.do(ctx, http.MethodGet, l.baseURL+"/domains", filter, nil)
	if err != nil {
		return 0, err
	}
	var resp domainsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, fmt.Errorf("decode linode domains: %w", err)
	}
	for _, d := range resp.Data {
		if d.Domain == zone {
			l.mu.Lock()
			l.domainID = d.ID
			l.mu.Unlock()
			return d.ID, nil
		}
	}
	return 0, fmt.Errorf("linode: domain %q not found: %w", zone, ErrNotFound)
}

func (l *linode) do(ctx context.Context, method, url, xfilter string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal linode request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, fmt.Errorf("create linode request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+l.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if xfilter != "" {
		req.Header.Set("X-Filter", xfilter)
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("linode API request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read linode response: %w", err)
	}
	if err := statusError("linode", resp.StatusCode, data, linodeErrReason); err != nil {
		return nil, err
	}
	return data, nil
}

// linodeErrReason extracts the human-readable reason(s) from a Linode error
// response body of the form {"errors":[{"field":...,"reason":...}]}.
func linodeErrReason(body []byte) string {
	var e struct {
		Errors []struct {
			Field  string `json:"field"`
			Reason string `json:"reason"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		reasons := make([]string, 0, len(e.Errors))
		for _, er := range e.Errors {
			if er.Field != "" {
				reasons = append(reasons, er.Field+": "+er.Reason)
			} else {
				reasons = append(reasons, er.Reason)
			}
		}
		return strings.Join(reasons, "; ")
	}
	if len(body) > 0 {
		return string(body)
	}
	return "(no body)"
}
