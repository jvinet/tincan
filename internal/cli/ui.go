package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
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

// tableCell pairs a display string (which may contain ANSI escapes) with
// its visible width in runes. Used by printer.table to align styled headers
// with unstyled data cells — stdlib text/tabwriter can't do this since its
// escape mechanism is for protecting tabs/newlines from being interpreted
// as cell separators, not for hiding bytes from the width calculation.
type tableCell struct {
	display string
	width   int
}

func plainCell(s string) tableCell {
	return tableCell{display: s, width: utf8.RuneCountInString(s)}
}

func (p *printer) styledCell(code, s string) tableCell {
	return tableCell{display: p.style(code, s), width: utf8.RuneCountInString(s)}
}

// table renders rows of cells into aligned columns. All rows must have the
// same length; widths auto-size to the widest visible content per column.
// indent is prepended to every row; gap is inserted between cells.
func (p *printer) table(indent, gap string, rows [][]tableCell) {
	if len(rows) == 0 {
		return
	}
	nCols := len(rows[0])
	widths := make([]int, nCols)
	for _, row := range rows {
		for i, c := range row {
			if i >= nCols {
				break
			}
			if c.width > widths[i] {
				widths[i] = c.width
			}
		}
	}
	for _, row := range rows {
		fmt.Fprint(p.w, indent)
		for i, c := range row {
			fmt.Fprint(p.w, c.display)
			if i < nCols-1 {
				if pad := widths[i] - c.width; pad > 0 {
					fmt.Fprint(p.w, strings.Repeat(" ", pad))
				}
				fmt.Fprint(p.w, gap)
			}
		}
		fmt.Fprintln(p.w)
	}
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
	label      string
	value      string
	secret     bool
	valueColor string
}

func kv(label, value string) pair     { return pair{label: label, value: value} }
func secret(label, value string) pair { return pair{label: label, value: value, secret: true} }
func kvColor(label, value, color string) pair {
	return pair{label: label, value: value, valueColor: color}
}

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
		} else if it.valueColor != "" {
			value = p.style(it.valueColor, value)
		}
		fmt.Fprintf(p.w, "  %s %s\n", styledLabel, value)
	}
}

