// Package dnsprovider abstracts the write side of a DNS hosting API so the
// "dns" dead-drop can publish the directory as TXT records through different
// providers. Only the admin (publisher) uses a provider; clients read the zone
// with an ordinary DNS lookup and never touch a provider API.
//
// This package must not import internal/drop: the drop package imports
// dnsprovider and maps the sentinel errors below onto its own (drop.ErrAuth,
// drop.ErrNotFound).
package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors returned by providers. The drop package translates these
// into its backend-neutral equivalents.
var (
	ErrAuth     = errors.New("dns provider: authentication failed")
	ErrNotFound = errors.New("dns provider: not found")
)

// TXTRecord is a single TXT resource record managed by a provider. ID is the
// provider's opaque identifier for the record, used to update or delete it.
type TXTRecord struct {
	ID    string
	Value string
}

// Provider is the write-side abstraction over a DNS hosting API. zone is the
// managed domain (e.g. "example.com"); name is the record's host label within
// the zone (e.g. "_tincan"). All operations target TXT records at name.
type Provider interface {
	// ListTXT returns every TXT record at name within zone.
	ListTXT(ctx context.Context, zone, name string) ([]TXTRecord, error)
	// CreateTXT adds a new TXT record holding value at name.
	CreateTXT(ctx context.Context, zone, name, value string) error
	// UpdateTXT replaces the value of the record identified by id.
	UpdateTXT(ctx context.Context, zone, id, value string) error
	// DeleteTXT removes the record identified by id.
	DeleteTXT(ctx context.Context, zone, id string) error
}

// Flusher is implemented by providers whose record writes are staged and must
// be committed with a separate call after a batch of changes — OVH's zone
// "refresh". The dns drop calls Flush once, after it has reconciled all
// records and only if it changed any. Providers that apply writes immediately
// (Linode, DigitalOcean) do not implement it, and the drop skips the call.
type Flusher interface {
	Flush(ctx context.Context, zone string) error
}

// Config selects and configures a provider. Token authenticates the
// single-token providers (Linode, DigitalOcean, Cloudflare). OVH instead
// authenticates with AppKey/AppSecret/ConsumerKey and selects a regional API
// endpoint by name (Endpoint, e.g. "ovh-eu"). BaseURL and HTTPClient are
// optional overrides used by tests.
type Config struct {
	Name  string
	Token string
	TTL   int

	// OVH application credentials and regional endpoint name (e.g. "ovh-eu").
	// Unused by the token providers.
	AppKey      string
	AppSecret   string
	ConsumerKey string
	Endpoint    string

	BaseURL    string
	HTTPClient *http.Client
}

// New constructs the provider named by cfg.Name.
func New(cfg Config) (Provider, error) {
	switch cfg.Name {
	case "linode":
		return newLinode(cfg), nil
	case "digitalocean":
		return newDigitalOcean(cfg), nil
	case "cloudflare":
		return newCloudflare(cfg), nil
	case "ovh":
		o, err := newOVH(cfg)
		if err != nil {
			return nil, err
		}
		return o, nil
	default:
		return nil, fmt.Errorf("unsupported dns provider %q", cfg.Name)
	}
}

// Supported reports whether name identifies a known provider. Used by config
// validation to reject typos early.
func Supported(name string) bool {
	switch name {
	case "linode", "digitalocean", "cloudflare", "ovh":
		return true
	default:
		return false
	}
}

// statusError maps an HTTP response status onto the package's sentinel errors
// (ErrAuth, ErrNotFound) or, for any other non-2xx, a formatted error naming
// the provider and the human-readable reason extracted from body. The status
// mapping is identical across providers; only the error wording differs, so
// each provider passes its own name and body-reason extractor.
func statusError(provider string, status int, body []byte, reason func([]byte) string) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ErrAuth
	case status == http.StatusNotFound:
		return ErrNotFound
	case status < 200 || status >= 300:
		return fmt.Errorf("%s API status %d: %s", provider, status, reason(body))
	default:
		return nil
	}
}
