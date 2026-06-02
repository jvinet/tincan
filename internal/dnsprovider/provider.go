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

// Config selects and configures a provider. Name and Token are required for
// real use; BaseURL and HTTPClient are optional overrides used by tests.
type Config struct {
	Name       string
	Token      string
	TTL        int
	BaseURL    string
	HTTPClient *http.Client
}

// New constructs the provider named by cfg.Name.
func New(cfg Config) (Provider, error) {
	switch cfg.Name {
	case "linode":
		return newLinode(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported dns provider %q", cfg.Name)
	}
}

// Supported reports whether name identifies a known provider. Used by config
// validation to reject typos early.
func Supported(name string) bool {
	switch name {
	case "linode":
		return true
	default:
		return false
	}
}
