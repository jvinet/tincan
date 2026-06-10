package drop

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jvinet/tincan/internal/directory"
)

type HTTP struct {
	url      string
	name     string
	username string
	password string
	client   *http.Client
}

func NewHTTP(rawURL, username, password string) *HTTP {
	return &HTTP{
		url:      rawURL,
		name:     "http:" + redactURL(rawURL),
		username: username,
		password: password,
		client: &http.Client{
			Timeout: 30 * time.Second,
			// A dead-drop serves the object directly; it has no legitimate
			// reason to redirect. Following one could turn every polling
			// client into an SSRF vector (cloud metadata, intranet hosts), so
			// refuse and surface it as an error rather than chase it.
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return fmt.Errorf("dead-drop redirected to %s; refusing to follow", req.URL.Redacted())
			},
		},
	}
}

// redactURL strips any userinfo (user:pass@) from a URL so it is safe to log
// or surface in status output. Falls back to the raw string if unparseable.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Redacted()
}

func (h *HTTP) Name() string { return h.name }

func (h *HTTP) Get(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return nil, fmt.Errorf("create HTTP GET: %w", err)
	}
	h.auth(req)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()
	if err := httpStatusError(resp.StatusCode); err != nil {
		return nil, err
	}
	if resp.ContentLength > directory.MaxBlobSize {
		return nil, fmt.Errorf("dead-drop object is %d bytes (max %d)", resp.ContentLength, directory.MaxBlobSize)
	}
	// The Content-Length check alone is insufficient: chunked responses omit
	// it, and the transport transparently decompresses Content-Encoding, so
	// the read itself must be bounded.
	data, err := io.ReadAll(io.LimitReader(resp.Body, directory.MaxBlobSize+1))
	if err != nil {
		return nil, fmt.Errorf("read HTTP response: %w", err)
	}
	if len(data) > directory.MaxBlobSize {
		return nil, fmt.Errorf("dead-drop object exceeds %d bytes", directory.MaxBlobSize)
	}
	return data, nil
}

func (h *HTTP) Put(context.Context, []byte) error {
	return ErrReadOnly
}

func (h *HTTP) Stat(ctx context.Context) (Metadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, h.url, nil)
	if err != nil {
		return Metadata{}, fmt.Errorf("create HTTP HEAD: %w", err)
	}
	h.auth(req)
	resp, err := h.client.Do(req)
	if err != nil {
		return Metadata{}, fmt.Errorf("HTTP HEAD: %w", err)
	}
	defer resp.Body.Close()
	if err := httpStatusError(resp.StatusCode); err != nil {
		return Metadata{}, err
	}
	meta := Metadata{UpdatedAt: time.Now(), ETag: strings.Trim(resp.Header.Get("ETag"), "\"")}
	if n, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil {
		meta.Size = n
	}
	if lastModified := resp.Header.Get("Last-Modified"); lastModified != "" {
		if t, err := http.ParseTime(lastModified); err == nil {
			meta.UpdatedAt = t
		}
	}
	return meta, nil
}

func (h *HTTP) auth(req *http.Request) {
	if h.username != "" || h.password != "" {
		req.SetBasicAuth(h.username, h.password)
	}
}

func httpStatusError(status int) error {
	switch {
	case status == http.StatusNotFound:
		return ErrNotFound
	case status == http.StatusUnauthorized:
		return ErrAuth
	case status == http.StatusForbidden:
		// Mirror the S3 backend: 403 means the request reached the object but
		// isn't permitted to read it (private object, missing public-read
		// grant) — a permission problem, not bad credentials. 401 is the
		// credentials failure.
		return ErrForbidden
	case status < 200 || status >= 300:
		return fmt.Errorf("dead-drop HTTP status %d", status)
	default:
		return nil
	}
}
