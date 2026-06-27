package dnsprovider

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
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

// ovhEndpoints maps OVH's named API regions to their base URLs (see the
// official go-ovh client). The drop selects one via the "endpoint" config key;
// "ovh-eu" is the default.
var ovhEndpoints = map[string]string{
	"ovh-eu":        "https://eu.api.ovh.com/1.0",
	"ovh-ca":        "https://ca.api.ovh.com/1.0",
	"ovh-us":        "https://api.us.ovhcloud.com/1.0",
	"kimsufi-eu":    "https://eu.api.kimsufi.com/1.0",
	"kimsufi-ca":    "https://ca.api.kimsufi.com/1.0",
	"soyoustart-eu": "https://eu.api.soyoustart.com/1.0",
	"soyoustart-ca": "https://ca.api.soyoustart.com/1.0",
}

// ovh implements Provider (and Flusher) against the OVH DNS API:
// https://api.ovh.com/console/#/domain/zone
//
// OVH differs from the token providers in three ways that shape this code:
//
//   - Auth is a per-request signature, not a bearer token. Each call carries
//     X-Ovh-Application/Consumer/Timestamp headers and an X-Ovh-Signature of
//     "$1$"+SHA1(AppSecret+"+"+ConsumerKey+"+"+METHOD+"+"+URL+"+"+body+"+"+ts).
//     The timestamp must track OVH's clock, so the server time is fetched once
//     and the local-vs-server delta cached.
//   - Listing records returns only their numeric ids; each record's value
//     needs a follow-up GET. ListTXT therefore issues 1+N requests.
//   - Writes are staged in the zone and only served after a POST .../refresh.
//     That commit is exposed through Flush (the Flusher interface), which the
//     drop calls once after reconciling.
type ovh struct {
	appKey      string
	appSecret   string
	consumerKey string
	ttl         int
	baseURL     string
	client      *http.Client

	mu        sync.Mutex
	delta     int64 // local Unix time minus OVH server time
	haveDelta bool
}

func newOVH(cfg Config) (*ovh, error) {
	base := cfg.BaseURL
	if base == "" {
		name := cfg.Endpoint
		if name == "" {
			name = "ovh-eu"
		}
		var ok bool
		if base, ok = ovhEndpoints[name]; !ok {
			return nil, fmt.Errorf("unknown ovh endpoint %q (want ovh-eu, ovh-ca, ovh-us, ...)", name)
		}
	}
	return &ovh{
		appKey:      cfg.AppKey,
		appSecret:   cfg.AppSecret,
		consumerKey: cfg.ConsumerKey,
		ttl:         cfg.TTL,
		baseURL:     base,
		client:      defaultHTTPClient(cfg),
	}, nil
}

// ovhRecord is both the response shape of GET .../record/{id} and the request
// body for create/update. omitempty lets one struct serve both: a create omits
// id; an update omits subDomain/fieldType (OVH's PUT alters only the supplied
// properties, leaving the record's name and type intact).
type ovhRecord struct {
	ID        int64  `json:"id,omitempty"`
	SubDomain string `json:"subDomain,omitempty"`
	FieldType string `json:"fieldType,omitempty"`
	Target    string `json:"target,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
}

func (o *ovh) ListTXT(ctx context.Context, zone, name string) ([]TXTRecord, error) {
	q := url.Values{}
	q.Set("fieldType", "TXT")
	q.Set("subDomain", name) // "" selects the zone apex
	var ids []int64
	if err := o.do(ctx, http.MethodGet, "/domain/zone/"+zone+"/record", q.Encode(), nil, &ids); err != nil {
		return nil, err
	}
	out := make([]TXTRecord, 0, len(ids))
	for _, id := range ids {
		var rec ovhRecord
		path := fmt.Sprintf("/domain/zone/%s/record/%d", zone, id)
		if err := o.do(ctx, http.MethodGet, path, "", nil, &rec); err != nil {
			return nil, err
		}
		// Belt-and-suspenders: the list filter already scopes to our TXT
		// subdomain; re-check in case the API ever broadens it.
		if rec.FieldType == "TXT" && strings.EqualFold(rec.SubDomain, name) {
			out = append(out, TXTRecord{ID: strconv.FormatInt(rec.ID, 10), Value: rec.Target})
		}
	}
	return out, nil
}

func (o *ovh) CreateTXT(ctx context.Context, zone, name, value string) error {
	body := ovhRecord{FieldType: "TXT", SubDomain: name, Target: value, TTL: o.ttl}
	return o.do(ctx, http.MethodPost, "/domain/zone/"+zone+"/record", "", body, nil)
}

func (o *ovh) UpdateTXT(ctx context.Context, zone, recordID, value string) error {
	// Partial update: sending target (and ttl) leaves the record's subDomain
	// and fieldType untouched.
	body := ovhRecord{Target: value, TTL: o.ttl}
	return o.do(ctx, http.MethodPut, fmt.Sprintf("/domain/zone/%s/record/%s", zone, recordID), "", body, nil)
}

func (o *ovh) DeleteTXT(ctx context.Context, zone, recordID string) error {
	return o.do(ctx, http.MethodDelete, fmt.Sprintf("/domain/zone/%s/record/%s", zone, recordID), "", nil, nil)
}

// Flush applies the staged record changes to the live zone. OVH does not serve
// edits until the zone is refreshed, so the drop calls this once after a batch.
func (o *ovh) Flush(ctx context.Context, zone string) error {
	return o.do(ctx, http.MethodPost, "/domain/zone/"+zone+"/refresh", "", nil, nil)
}

func (o *ovh) do(ctx context.Context, method, path, rawQuery string, reqBody, out any) error {
	fullURL := o.baseURL + path
	if rawQuery != "" {
		fullURL += "?" + rawQuery
	}
	var body []byte
	if reqBody != nil {
		var err error
		if body, err = json.Marshal(reqBody); err != nil {
			return fmt.Errorf("marshal ovh request: %w", err)
		}
	}
	ts, err := o.timestamp(ctx)
	if err != nil {
		return err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return fmt.Errorf("create ovh request: %w", err)
	}
	req.Header.Set("X-Ovh-Application", o.appKey)
	req.Header.Set("X-Ovh-Consumer", o.consumerKey)
	req.Header.Set("X-Ovh-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Ovh-Signature", o.sign(method, fullURL, body, ts))
	if body != nil {
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("ovh API request: %w", err)
	}
	defer resp.Body.Close()
	data, err := readResponseBody("ovh", resp.Body)
	if err != nil {
		return err
	}
	if err := statusError("ovh", resp.StatusCode, data, ovhErrReason); err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode ovh response: %w", err)
		}
	}
	return nil
}

// sign builds the X-Ovh-Signature header. SHA-1 is mandated by the OVH signing
// scheme; it is not a security choice of ours.
func (o *ovh) sign(method, fullURL string, body []byte, ts int64) string {
	h := sha1.New()
	h.Write([]byte(o.appSecret + "+" + o.consumerKey + "+" + method + "+" + fullURL + "+" + string(body) + "+" + strconv.FormatInt(ts, 10)))
	return "$1$" + hex.EncodeToString(h.Sum(nil))
}

// timestamp returns the current OVH server time (seconds), correcting for local
// clock skew. The server time is fetched once via the unauthenticated
// /auth/time endpoint and the delta cached; a signature built on a skewed clock
// is rejected.
func (o *ovh) timestamp(ctx context.Context) (int64, error) {
	o.mu.Lock()
	have, delta := o.haveDelta, o.delta
	o.mu.Unlock()
	if !have {
		st, err := o.serverTime(ctx)
		if err != nil {
			return 0, err
		}
		delta = time.Now().Unix() - st
		o.mu.Lock()
		o.delta, o.haveDelta = delta, true
		o.mu.Unlock()
	}
	return time.Now().Unix() - delta, nil
}

func (o *ovh) serverTime(ctx context.Context) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/auth/time", nil)
	if err != nil {
		return 0, fmt.Errorf("create ovh time request: %w", err)
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("ovh time request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return 0, fmt.Errorf("read ovh server time: %w", err)
	}
	if err := statusError("ovh", resp.StatusCode, data, ovhErrReason); err != nil {
		return 0, err
	}
	t, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse ovh server time %q: %w", string(data), err)
	}
	return t, nil
}

// ovhErrReason extracts the human-readable message from an OVH error body of
// the form {"message":"...","errorCode":"..."}.
func ovhErrReason(body []byte) string {
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
