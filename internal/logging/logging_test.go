package logging

import (
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"INFO":    slog.LevelInfo,
		"debug":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"err":     slog.LevelError,
		"bogus":   slog.LevelInfo,
		" DEBUG ": slog.LevelDebug,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestQuoteUnambiguous(t *testing.T) {
	cases := map[string]string{
		"hello":          "hello",
		"hello world":    `"hello world"`,
		`with"quote`:     `"with\"quote"`,
		"with=equals":    `"with=equals"`,
		"":               `""`,
		"trailing\ttab":  `"trailing\ttab"`,
		"plain.key-name": "plain.key-name",
	}
	for in, want := range cases {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNeedsQuoting(t *testing.T) {
	if !needsQuoting("") {
		t.Error("empty string should be quoted")
	}
	if needsQuoting("hello") {
		t.Error("simple word should not need quoting")
	}
	if !needsQuoting("a b") {
		t.Error("space requires quoting")
	}
}

func TestAppendAttrSimple(t *testing.T) {
	var b strings.Builder
	appendAttr(&b, "", slog.Int("count", 42))
	if got := b.String(); got != "count=42" {
		t.Errorf("got %q want %q", got, "count=42")
	}

	b.Reset()
	appendAttr(&b, "", slog.String("name", "alice"))
	if got := b.String(); got != "name=alice" {
		t.Errorf("got %q want %q", got, "name=alice")
	}

	b.Reset()
	appendAttr(&b, "", slog.String("msg", "two words"))
	if got := b.String(); got != `msg="two words"` {
		t.Errorf("got %q want %q", got, `msg="two words"`)
	}
}

func TestLevelString(t *testing.T) {
	cases := map[slog.Level]string{
		slog.LevelDebug: "DEBUG",
		slog.LevelInfo:  "INFO",
		slog.LevelWarn:  "WARN",
		slog.LevelError: "ERROR",
	}
	for l, want := range cases {
		if got := levelString(l); got != want {
			t.Errorf("levelString(%v) = %q, want %q", l, got, want)
		}
	}
}
