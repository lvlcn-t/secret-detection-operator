package validation

import (
	"fmt"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// maxLen is the maximum length of a DNS-1123 subdomain.
const maxLen = 253

// invalidChar matches anything not a lower-case letter or digit
var invalidChar = regexp.MustCompile(`[^a-z0-9]`)

// MakeDNS1123Subdomain takes an arbitrary string and
// turns it into a safe DNS-1123 subdomain:
//
//   - to lower case
//   - replace invalid chars with '-'
//   - collapse multiple '-' into one (optional)
//   - trim leading/trailing '-'
//   - (optional) enforce max length of 253 chars
func MakeDNS1123Subdomain(s string) string {
	s = strings.ToLower(s)
	s = invalidChar.ReplaceAllString(s, "-")

	// collapse runs of hyphens:
	s = strings.ReplaceAll(s, "--", "-")

	s = strings.Trim(s, "-")
	if s == "" {
		return "unknown"
	}

	if len(s) > maxLen {
		s = s[:maxLen]
		s = strings.TrimRight(s, "-")
	}
	return s
}

// ValidateDNS1123Subdomain returns nil if name is valid,
// otherwise an error describing what’s invalid.
func ValidateDNS1123Subdomain(name string) error {
	errs := validation.IsDNS1123Subdomain(name)
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid DNS-1123 subdomain %q: %s", name, strings.Join(errs, "; "))
}
