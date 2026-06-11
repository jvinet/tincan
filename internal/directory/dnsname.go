package directory

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// NormalizeDomain returns domain in the form the directory stores: lowercase,
// with a single trailing dot (a fully-qualified spelling) stripped. Callers
// normalize operator input before validating or persisting it.
func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// ValidateLabel checks that name works as a single DNS label: 1–63 characters
// of letters, digits, and hyphens, not starting or ending with a hyphen
// (RFC 1123). Case is allowed — DNS matching is case-insensitive, and tincan
// lowercases labels wherever it renders them.
func ValidateLabel(name string) error {
	if name == "" {
		return errors.New("empty")
	}
	if len(name) > 63 {
		return fmt.Errorf("%d characters long (DNS labels max out at 63)", len(name))
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return errors.New("must not start or end with a hyphen")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return fmt.Errorf("contains %q (only letters, digits, and hyphens are allowed)", c)
		}
	}
	return nil
}

// ValidateDomain checks that domain is a syntactically valid DNS domain in
// its normalized form: one or more dot-separated labels, ≤253 characters
// total, already lowercase with no trailing dot (run NormalizeDomain first).
// Anything that parses as an IP address is rejected — "10.42.0.0" as a
// domain is always an input mistake.
func ValidateDomain(domain string) error {
	if domain == "" {
		return errors.New("empty domain")
	}
	if len(domain) > 253 {
		return fmt.Errorf("%d characters long (DNS names max out at 253)", len(domain))
	}
	if domain != NormalizeDomain(domain) {
		return errors.New("must be lowercase with no trailing dot")
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return errors.New("is an IP address, not a domain")
	}
	for label := range strings.SplitSeq(domain, ".") {
		if err := ValidateLabel(label); err != nil {
			return fmt.Errorf("label %q: %v", label, err)
		}
	}
	return nil
}
