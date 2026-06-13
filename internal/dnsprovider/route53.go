package dnsprovider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultRoute53BaseURL = "https://route53.amazonaws.com"
	route53APIVersion     = "2013-04-01"
	// Route 53 is a global service reached through one endpoint that always
	// signs as us-east-1 / "route53" in the standard AWS partition.
	route53Region  = "us-east-1"
	route53Service = "route53"
	// route53XMLNS is the namespace Route 53 requires on a change request's root
	// element. It is emitted as a plain attribute (see changeRRSetsRequest).
	route53XMLNS = "https://route53.amazonaws.com/doc/2013-04-01/"
)

// route53 implements Provider and Replacer against the Amazon Route 53 DNS API:
// https://docs.aws.amazon.com/Route53/latest/APIReference/
//
// Route 53 differs from the other providers in three ways that shape this file:
//
//   - Authentication is an AWS Signature Version 4 request signature derived
//     from an access key id and secret access key, not a bearer token. Each
//     request carries an X-Amz-Date header and an Authorization header computed
//     by awsSignV4. Route 53 always signs as us-east-1 / "route53".
//   - The API speaks XML, not JSON: requests and responses are marshaled with
//     encoding/xml.
//   - Like deSEC, Route 53 has no individually-addressable records. The TXT
//     records at a name form one ResourceRecordSet (RRset), changed atomically
//     with an UPSERT (create-or-replace-the-whole-set). So ReplaceTXT — the path
//     the dns drop uses — is a single UPSERT, with no half-updated window. The
//     per-record Provider methods are still implemented (read-modify-write over
//     the RRset, keyed on the record value) so route53 is a complete Provider.
//
// As with deSEC, TXT values are stored in DNS presentation format (double
// quoted); the quotes are added on write and stripped on read. tincan's chunk
// values are base64url plus "tc1;<seq>;<total>;" — no quotes or backslashes —
// so no further escaping is needed, and each chunk stays under the 255-byte
// character-string limit (one quoted string per value).
type route53 struct {
	accessKey string
	secretKey string
	ttl       int
	baseURL   string
	client    *http.Client

	mu     sync.Mutex
	zoneID string // cached zone name -> hosted zone id (without "/hostedzone/")
}

func newRoute53(cfg Config) *route53 {
	base := cfg.BaseURL
	if base == "" {
		base = defaultRoute53BaseURL
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 300
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &route53{
		accessKey: cfg.AccessKey,
		secretKey: cfg.SecretKey,
		ttl:       ttl,
		baseURL:   base,
		client:    hc,
	}
}

// r53RRSet is both a parsed RRset (in a list response) and the RRset carried in
// a change request. ResourceRecords holds TXT values in presentation format.
type r53RRSet struct {
	Name            string      `xml:"Name"`
	Type            string      `xml:"Type"`
	TTL             int         `xml:"TTL"`
	ResourceRecords []r53Record `xml:"ResourceRecords>ResourceRecord"`
}

type r53Record struct {
	Value string `xml:"Value"`
}

type listHostedZonesByNameResponse struct {
	XMLName     xml.Name        `xml:"ListHostedZonesByNameResponse"`
	HostedZones []r53HostedZone `xml:"HostedZones>HostedZone"`
}

type r53HostedZone struct {
	ID   string `xml:"Id"`
	Name string `xml:"Name"`
}

type listResourceRecordSetsResponse struct {
	XMLName xml.Name   `xml:"ListResourceRecordSetsResponse"`
	RRSets  []r53RRSet `xml:"ResourceRecordSets>ResourceRecordSet"`
}

// changeRRSetsRequest is the body of a ChangeResourceRecordSets call. The
// namespace is carried as a plain xmlns attribute rather than via xml.Name's
// space: that keeps Go's encoder from emitting xmlns="" resets on the child
// elements (which would put them in the wrong namespace and Route 53 would
// reject the batch), while the declared default namespace still applies to
// every unprefixed descendant.
type changeRRSetsRequest struct {
	XMLName     xml.Name       `xml:"ChangeResourceRecordSetsRequest"`
	XMLNS       string         `xml:"xmlns,attr"`
	ChangeBatch r53ChangeBatch `xml:"ChangeBatch"`
}

type r53ChangeBatch struct {
	Changes []r53Change `xml:"Changes>Change"`
}

type r53Change struct {
	Action            string   `xml:"Action"`
	ResourceRecordSet r53RRSet `xml:"ResourceRecordSet"`
}

// ReplaceTXT publishes values as the complete TXT RRset at name in one atomic
// UPSERT — Route 53 replaces the whole RRset, creating it if absent. This is the
// path the dns drop uses for route53.
func (r *route53) ReplaceTXT(ctx context.Context, zone, name string, values []string) error {
	return r.putValues(ctx, zone, name, values)
}

func (r *route53) ListTXT(ctx context.Context, zone, name string) ([]TXTRecord, error) {
	values, err := r.getValues(ctx, zone, name)
	if err != nil {
		return nil, err
	}
	out := make([]TXTRecord, 0, len(values))
	for _, v := range values {
		out = append(out, TXTRecord{ID: r53ID(name, v), Value: v})
	}
	return out, nil
}

func (r *route53) CreateTXT(ctx context.Context, zone, name, value string) error {
	values, err := r.getValues(ctx, zone, name)
	if err != nil {
		return err
	}
	return r.putValues(ctx, zone, name, append(values, value))
}

func (r *route53) UpdateTXT(ctx context.Context, zone, id, value string) error {
	name, old := splitR53ID(id)
	values, err := r.getValues(ctx, zone, name)
	if err != nil {
		return err
	}
	for i, v := range values {
		if v == old {
			values[i] = value
			break
		}
	}
	return r.putValues(ctx, zone, name, values)
}

func (r *route53) DeleteTXT(ctx context.Context, zone, id string) error {
	name, old := splitR53ID(id)
	values, err := r.getValues(ctx, zone, name)
	if err != nil {
		return err
	}
	out := values[:0]
	for _, v := range values {
		if v != old {
			out = append(out, v)
		}
	}
	return r.putValues(ctx, zone, name, out)
}

// getValues returns the (unquoted) TXT values of the RRset at name, or nil if
// there is no such RRset yet — a normal first-publish state.
func (r *route53) getValues(ctx context.Context, zone, name string) ([]string, error) {
	rr, err := r.getRecordSet(ctx, zone, name)
	if err != nil || rr == nil {
		return nil, err
	}
	out := make([]string, 0, len(rr.ResourceRecords))
	for _, rec := range rr.ResourceRecords {
		out = append(out, unquoteTXT(rec.Value))
	}
	return out, nil
}

// getRecordSet returns the TXT RRset at name, or nil if there is none.
// ListResourceRecordSets takes name+type as a *starting point* (records are
// returned in lexicographic order from there), not a strict filter, so the
// returned set's name and type are matched exactly here.
func (r *route53) getRecordSet(ctx context.Context, zone, name string) (*r53RRSet, error) {
	id, err := r.resolveZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	fqdn := r53FQDN(name, zone)
	q := url.Values{}
	q.Set("name", fqdn)
	q.Set("type", "TXT")
	reqURL := fmt.Sprintf("%s/%s/hostedzone/%s/rrset?%s", r.baseURL, route53APIVersion, id, awsCanonicalQuery(q))
	data, err := r.do(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	var resp listResourceRecordSetsResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode route53 record sets: %w", err)
	}
	for i := range resp.RRSets {
		rr := &resp.RRSets[i]
		if strings.EqualFold(rr.Type, "TXT") && strings.EqualFold(strings.TrimSuffix(rr.Name, "."), fqdn) {
			return rr, nil
		}
	}
	return nil, nil
}

// putValues replaces the TXT RRset at name with values via an UPSERT (quoting
// each for presentation format), creating the RRset if absent. An empty set
// deletes the RRset, which Route 53 requires be expressed as a DELETE carrying
// the set's exact current contents.
func (r *route53) putValues(ctx context.Context, zone, name string, values []string) error {
	if len(values) == 0 {
		return r.deleteRecordSet(ctx, zone, name)
	}
	records := make([]r53Record, len(values))
	for i, v := range values {
		records[i] = r53Record{Value: `"` + v + `"`} // presentation format; values are quote/backslash-free
	}
	rr := r53RRSet{Name: r53FQDN(name, zone), Type: "TXT", TTL: r.ttl, ResourceRecords: records}
	return r.change(ctx, zone, "UPSERT", rr)
}

func (r *route53) deleteRecordSet(ctx context.Context, zone, name string) error {
	rr, err := r.getRecordSet(ctx, zone, name)
	if err != nil || rr == nil {
		return err
	}
	// A DELETE must echo the RRset's exact current Name/Type/TTL/records.
	return r.change(ctx, zone, "DELETE", *rr)
}

func (r *route53) change(ctx context.Context, zone, action string, rr r53RRSet) error {
	id, err := r.resolveZoneID(ctx, zone)
	if err != nil {
		return err
	}
	body := changeRRSetsRequest{
		XMLNS: route53XMLNS,
		ChangeBatch: r53ChangeBatch{
			Changes: []r53Change{{Action: action, ResourceRecordSet: rr}},
		},
	}
	reqURL := fmt.Sprintf("%s/%s/hostedzone/%s/rrset/", r.baseURL, route53APIVersion, id)
	_, err = r.do(ctx, http.MethodPost, reqURL, body)
	return err
}

// resolveZoneID maps a zone name to its Route 53 hosted-zone id (without the
// "/hostedzone/" prefix), caching the result so a publish issues a single
// lookup. ListHostedZonesByName returns zones ordered lexicographically from
// dnsname, so the first result is our zone iff it exists; no match becomes
// ErrNotFound.
func (r *route53) resolveZoneID(ctx context.Context, zone string) (string, error) {
	r.mu.Lock()
	cached := r.zoneID
	r.mu.Unlock()
	if cached != "" {
		return cached, nil
	}
	q := url.Values{}
	q.Set("dnsname", zone)
	q.Set("maxitems", "1")
	reqURL := fmt.Sprintf("%s/%s/hostedzonesbyname?%s", r.baseURL, route53APIVersion, awsCanonicalQuery(q))
	data, err := r.do(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	var resp listHostedZonesByNameResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("decode route53 hosted zones: %w", err)
	}
	want := strings.TrimSuffix(zone, ".")
	for _, hz := range resp.HostedZones {
		if strings.EqualFold(strings.TrimSuffix(hz.Name, "."), want) {
			zid := strings.TrimPrefix(hz.ID, "/hostedzone/")
			r.mu.Lock()
			r.zoneID = zid
			r.mu.Unlock()
			return zid, nil
		}
	}
	return "", fmt.Errorf("route53: hosted zone %q not found: %w", zone, ErrNotFound)
}

func (r *route53) do(ctx context.Context, method, reqURL string, body any) ([]byte, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = xml.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal route53 request: %w", err)
		}
	}
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, rdr)
	if err != nil {
		return nil, fmt.Errorf("create route53 request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/xml")
	}
	awsSignV4(req, r.accessKey, r.secretKey, route53Region, route53Service, payload, time.Now())
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("route53 API request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read route53 response: %w", err)
	}
	if err := statusError("route53", resp.StatusCode, data, route53ErrReason); err != nil {
		return nil, err
	}
	return data, nil
}

// r53FQDN builds the fully-qualified name Route 53 stores and matches on. An
// empty or "@" label targets the zone apex, whose record name is the bare zone.
func r53FQDN(name, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	name = strings.TrimSuffix(name, ".")
	if name == "" || name == "@" {
		return zone
	}
	return name + "." + zone
}

// r53ID encodes the record name alongside the value. The per-record mutators
// receive only this opaque id, not the name, so the name travels with it to
// locate the RRset for the read-modify-write. "/" is a safe separator: it
// appears in neither DNS names nor tincan's base64url chunk values.
func r53ID(name, value string) string { return name + "/" + value }

func splitR53ID(id string) (name, value string) {
	if before, after, found := strings.Cut(id, "/"); found {
		return before, after
	}
	return "", id
}

// route53ErrReason extracts the human-readable message from a Route 53 XML error
// body of the form <ErrorResponse><Error><Code/><Message/></Error></ErrorResponse>.
func route53ErrReason(body []byte) string {
	var e struct {
		Error struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		} `xml:"Error"`
	}
	if xml.Unmarshal(body, &e) == nil {
		switch {
		case e.Error.Code != "" && e.Error.Message != "":
			return e.Error.Code + ": " + e.Error.Message
		case e.Error.Message != "":
			return e.Error.Message
		case e.Error.Code != "":
			return e.Error.Code
		}
	}
	if len(body) > 0 {
		return string(body)
	}
	return "(no body)"
}

// awsSignV4 signs req in place with AWS Signature Version 4, setting the
// X-Amz-Date and Authorization headers. It signs the host and x-amz-date
// headers, which is the minimum Route 53 requires; payload is the exact request
// body (nil for a bodyless GET). region and service are signing parameters, not
// derived from the URL, so the pure signing math can be exercised against AWS's
// published test vectors. See
// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
func awsSignV4(req *http.Request, accessKey, secretKey, region, service string, payload []byte, t time.Time) {
	t = t.UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	// Our paths contain only unreserved characters (the fixed API version, the
	// literal path segments, and an [A-Z0-9] hosted-zone id), so EscapedPath is
	// already the canonical, URI-encoded form SigV4 wants.
	canonicalHeaders := "host:" + host + "\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-date"
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		awsCanonicalQuery(req.URL.Query()),
		canonicalHeaders,
		signedHeaders,
		sha256Hex(payload),
	}, "\n")

	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := awsSigningKey(secretKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, scope, signedHeaders, signature))
}

// awsSigningKey derives the SigV4 signing key by the successive-HMAC schedule.
func awsSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// awsCanonicalQuery builds the SigV4 canonical query string: each key and value
// URI-encoded, then sorted by key (and value). Returns "" for no parameters.
func awsCanonicalQuery(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		vals := append([]string(nil), v[k]...)
		sort.Strings(vals)
		ek := awsURIEncode(k)
		for _, val := range vals {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(ek)
			b.WriteByte('=')
			b.WriteString(awsURIEncode(val))
		}
	}
	return b.String()
}

// awsURIEncode applies AWS's UriEncode rules to a query component: RFC 3986
// percent-encoding that leaves the unreserved set (A-Za-z0-9-_.~) intact and
// encodes a space as %20 rather than "+".
func awsURIEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
