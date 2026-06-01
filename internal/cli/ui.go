package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

type printer struct {
	w     io.Writer
	color bool
}

func newPrinter(w io.Writer) *printer {
	return &printer{w: w, color: useColor(w)}
}

func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if term := os.Getenv("TERM"); term == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (p *printer) style(code, s string) string {
	if !p.color {
		return s
	}
	return code + s + ansiReset
}

// dimCell returns s wrapped in a dim ANSI escape, surrounded by tabwriter's
// escape markers (\xff) so the styled cell aligns correctly inside a
// tabwriter.NewWriter created with the tabwriter.StripEscape flag. Without
// the markers, tabwriter counts the ANSI bytes as visible width and the
// header row drifts away from the data rows.
func dimCell(p *printer, s string) string {
	if !p.color {
		return s
	}
	return "\xff" + ansiDim + "\xff" + s + "\xff" + ansiReset + "\xff"
}

func (p *printer) blank() {
	fmt.Fprintln(p.w)
}

func (p *printer) headline(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(p.w, "%s %s\n", p.style(ansiGreen+ansiBold, "✓"), p.style(ansiBold, msg))
}

func (p *printer) section(title string) {
	fmt.Fprintln(p.w, p.style(ansiBold+ansiCyan, title))
}

func (p *printer) hint(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(p.w, p.style(ansiDim, msg))
}

func (p *printer) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(p.w, "%s %s\n", p.style(ansiYellow+ansiBold, "!"), p.style(ansiYellow, msg))
}

func (p *printer) fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(p.w, "%s %s\n", p.style(ansiRed+ansiBold, "✗"), p.style(ansiRed, msg))
}

type pair struct {
	label  string
	value  string
	secret bool
}

func kv(label, value string) pair     { return pair{label: label, value: value} }
func secret(label, value string) pair { return pair{label: label, value: value, secret: true} }

func (p *printer) pairs(items ...pair) {
	maxLabel := 0
	for _, it := range items {
		if l := len(it.label); l > maxLabel {
			maxLabel = l
		}
	}
	for _, it := range items {
		label := it.label + ":" + strings.Repeat(" ", maxLabel-len(it.label))
		styledLabel := p.style(ansiDim, label)
		value := it.value
		if it.secret {
			value = p.style(ansiYellow, value) + " " + p.style(ansiDim, "[secret]")
		}
		fmt.Fprintf(p.w, "  %s %s\n", styledLabel, value)
	}
}

