package nostr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/coder/websocket"
)

// Filter is the subset of a NIP-01 REQ filter the nostr drop sends. Relays are
// not obliged to honor it, so the drop re-checks every returned event.
type Filter struct {
	Authors []string `json:"authors,omitempty"`
	Kinds   []int    `json:"kinds,omitempty"`
	DTags   []string `json:"#d,omitempty"`
	Limit   int      `json:"limit,omitempty"`
}

// Conn is one open relay connection. The drop talks to relays only through this
// interface, so tests substitute an in-memory fake — mirroring how the dns drop
// injects a lookupFunc.
type Conn interface {
	Publish(ctx context.Context, e Event) error
	Query(ctx context.Context, f Filter) ([]Event, error)
	Close() error
}

// Dialer opens a Conn to relayURL. DefaultDialer dials a real relay over
// WebSocket; tests pass their own.
type Dialer func(ctx context.Context, relayURL string) (Conn, error)

// RelayError reports that a relay refused an event (an OK,false response) or a
// subscription (a CLOSED response). Reason is the relay's machine-readable
// message, conventionally prefixed (NIP-01/NIP-20) with "auth-required:",
// "restricted:", "blocked:", "rate-limited:", "invalid:", etc.
type RelayError struct {
	Reason string
}

func (e *RelayError) Error() string {
	if e.Reason == "" {
		return "relay rejected request"
	}
	return "relay rejected request: " + e.Reason
}

// maxRelayMessage caps a single inbound relay frame. The drop enforces the
// authoritative directory.MaxBlobSize after base64-decoding the event content;
// this is a coarse transport guard so a hostile relay cannot stream unbounded
// data. base64 of a 4 MiB blob is ~5.6 MiB, so 16 MiB leaves ample headroom.
const maxRelayMessage = 16 << 20

type wsConn struct {
	url  string
	conn *websocket.Conn
}

// DefaultDialer connects to a relay over WebSocket, honoring ctx for the dial.
func DefaultDialer(ctx context.Context, relayURL string) (Conn, error) {
	c, _, err := websocket.Dial(ctx, relayURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial relay %s: %w", relayURL, err)
	}
	c.SetReadLimit(maxRelayMessage)
	return &wsConn{url: relayURL, conn: c}, nil
}

func (w *wsConn) Close() error {
	return w.conn.Close(websocket.StatusNormalClosure, "")
}

// Publish sends the event and waits for the relay's OK for that event id,
// skipping unrelated frames (NOTICE, or OKs for other ids).
func (w *wsConn) Publish(ctx context.Context, e Event) error {
	msg, err := json.Marshal([]any{"EVENT", e})
	if err != nil {
		return err
	}
	if err := w.conn.Write(ctx, websocket.MessageText, msg); err != nil {
		return fmt.Errorf("write EVENT to %s: %w", w.url, err)
	}
	for {
		typ, raw, err := w.readMessage(ctx)
		if err != nil {
			return err
		}
		if typ != "OK" || len(raw) < 3 {
			continue
		}
		var id string
		_ = json.Unmarshal(raw[1], &id)
		if id != e.ID {
			continue
		}
		var ok bool
		_ = json.Unmarshal(raw[2], &ok)
		if ok {
			return nil
		}
		var reason string
		if len(raw) >= 4 {
			_ = json.Unmarshal(raw[3], &reason)
		}
		return &RelayError{Reason: reason}
	}
}

// Query subscribes for stored events matching f and returns them once the relay
// signals end-of-stored-events. It does not stay subscribed for live events: a
// dead drop wants the current value, not a stream.
func (w *wsConn) Query(ctx context.Context, f Filter) ([]Event, error) {
	const subID = "tc"
	req, err := json.Marshal([]any{"REQ", subID, f})
	if err != nil {
		return nil, err
	}
	if err := w.conn.Write(ctx, websocket.MessageText, req); err != nil {
		return nil, fmt.Errorf("write REQ to %s: %w", w.url, err)
	}
	var events []Event
	for {
		typ, raw, err := w.readMessage(ctx)
		if err != nil {
			return events, err
		}
		switch typ {
		case "EVENT":
			if len(raw) < 3 {
				continue
			}
			var ev Event
			if err := json.Unmarshal(raw[2], &ev); err != nil {
				continue // skip malformed; the drop verifies survivors anyway
			}
			events = append(events, ev)
		case "EOSE":
			_ = w.writeMessage(ctx, []any{"CLOSE", subID})
			return events, nil
		case "CLOSED":
			var reason string
			if len(raw) >= 3 {
				_ = json.Unmarshal(raw[2], &reason)
			}
			return events, &RelayError{Reason: reason}
		}
	}
}

// readMessage reads one relay frame and returns its message type (element 0) and
// the full decoded array. Frames that are not a JSON array with a string type
// are skipped transparently.
func (w *wsConn) readMessage(ctx context.Context) (string, []json.RawMessage, error) {
	for {
		_, data, err := w.conn.Read(ctx)
		if err != nil {
			return "", nil, fmt.Errorf("read from %s: %w", w.url, err)
		}
		var raw []json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil || len(raw) == 0 {
			continue
		}
		var typ string
		if err := json.Unmarshal(raw[0], &typ); err != nil {
			continue
		}
		return typ, raw, nil
	}
}

func (w *wsConn) writeMessage(ctx context.Context, v any) error {
	msg, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return w.conn.Write(ctx, websocket.MessageText, msg)
}

// NormalizeRelayURL lowercases the scheme and host and trims a trailing slash so
// duplicate relay entries collapse to one. It requires a ws:// or wss:// URL.
func NormalizeRelayURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid relay url %q: %w", raw, err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return "", fmt.Errorf("relay url %q must be ws:// or wss://", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("relay url %q has no host", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u.String(), nil
}
