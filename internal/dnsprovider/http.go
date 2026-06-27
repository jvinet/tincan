package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const apiResponseLimit = 1 << 20

func defaultHTTPClient(cfg Config) *http.Client {
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func doJSON(ctx context.Context, client *http.Client, provider, method, reqURL string, body any, configure func(*http.Request), reason func([]byte) string) ([]byte, error) {
	status, data, err := doJSONRaw(ctx, client, provider, method, reqURL, body, configure)
	if err != nil {
		return nil, err
	}
	if err := statusError(provider, status, data, reason); err != nil {
		return nil, err
	}
	return data, nil
}

func doJSONRaw(ctx context.Context, client *http.Client, provider, method, reqURL string, body any, configure func(*http.Request)) (int, []byte, error) {
	rdr, hasBody, err := jsonBody(provider, body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("create %s request: %w", provider, err)
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	if configure != nil {
		configure(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s API request: %w", provider, err)
	}
	defer resp.Body.Close()
	data, err := readResponseBody(provider, resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, data, nil
}

func jsonBody(provider string, body any) (io.Reader, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, false, fmt.Errorf("marshal %s request: %w", provider, err)
	}
	return bytes.NewReader(b), true, nil
}

func readResponseBody(provider string, body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, apiResponseLimit))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", provider, err)
	}
	return data, nil
}
