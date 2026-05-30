// Package logging configures slog.Default() to write to syslog.
//
// User-facing console output (the printer in internal/cli/ui.go) is the
// supported way to communicate with the operator running tincan
// interactively. The slog logger configured here is for persistent debugging
// and monitoring: every state-changing command and the daemon write
// machine-parseable events to the OS syslog, which survives daemon restarts
// and can be tailed or shipped off-host.
//
// Verbosity is controlled by TINCAN_LOG_LEVEL (debug|info|warn|error,
// default info). Where syslog isn't reachable, falls back to a text handler
// on stderr — useful for tests and unusual deployments.
package logging

import (
	"context"
	"fmt"
	"log/slog"
	"log/syslog"
	"os"
	"strings"
)

const EnvLevel = "TINCAN_LOG_LEVEL"

// Init replaces slog.Default() with a logger that writes to syslog using the
// given tag (typically "tincan"). Safe to call multiple times; the most
// recent call wins. If syslog is unreachable, falls back to stderr.
func Init(tag string) {
	level := ParseLevel(os.Getenv(EnvLevel))
	if w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, tag); err == nil {
		slog.SetDefault(slog.New(&syslogHandler{w: w, level: level}))
		return
	}
	opts := &slog.HandlerOptions{Level: level}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))
}

// ParseLevel maps a string (case-insensitive) to a slog.Level. Unknown values
// default to LevelInfo.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// syslogHandler emits each slog.Record as one syslog line in logfmt form:
// `level=INFO msg="..." key=val key=val`. Syslog itself supplies the
// timestamp, hostname, and tag, so we don't repeat those.
type syslogHandler struct {
	w     *syslog.Writer
	level slog.Level
	attrs []slog.Attr
	group string
}

func (h *syslogHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *syslogHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	fmt.Fprintf(&b, "level=%s msg=%s", levelString(r.Level), quote(r.Message))
	for _, a := range h.attrs {
		b.WriteByte(' ')
		appendAttr(&b, h.group, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		b.WriteByte(' ')
		appendAttr(&b, h.group, a)
		return true
	})
	msg := b.String()
	switch {
	case r.Level >= slog.LevelError:
		return h.w.Err(msg)
	case r.Level >= slog.LevelWarn:
		return h.w.Warning(msg)
	case r.Level >= slog.LevelInfo:
		return h.w.Info(msg)
	default:
		return h.w.Debug(msg)
	}
}

func (h *syslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append([]slog.Attr{}, h.attrs...)
	n.attrs = append(n.attrs, attrs...)
	return &n
}

func (h *syslogHandler) WithGroup(name string) slog.Handler {
	n := *h
	if h.group == "" {
		n.group = name
	} else {
		n.group = h.group + "." + name
	}
	return &n
}

func appendAttr(b *strings.Builder, group string, a slog.Attr) {
	key := a.Key
	if group != "" {
		key = group + "." + key
	}
	b.WriteString(key)
	b.WriteByte('=')
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		b.WriteString(quote(v.String()))
	case slog.KindGroup:
		// Inline group attrs as `group.key=...`.
		nested := group
		if nested == "" {
			nested = a.Key
		} else {
			nested = nested + "." + a.Key
		}
		// Reset what we just wrote (the "key=" prefix) since group has no value.
		// Easiest: truncate. Trade-off: extra allocation.
		s := b.String()
		s = s[:len(s)-len(key)-1] // remove "key="
		b.Reset()
		b.WriteString(s)
		for i, ga := range v.Group() {
			if i > 0 {
				b.WriteByte(' ')
			}
			appendAttr(b, nested, ga)
		}
	default:
		s := v.String()
		if needsQuoting(s) {
			b.WriteString(quote(s))
		} else {
			b.WriteString(s)
		}
	}
}

func levelString(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARN"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	return strings.ContainsAny(s, " =\"\t\n\r")
}

func quote(s string) string {
	if !needsQuoting(s) {
		return s
	}
	return fmt.Sprintf("%q", s)
}
