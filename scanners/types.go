package scanners

import (
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Name represents the name of a secret scanner.
type Name string

// String returns the string representation of the scanner name.
func (s Name) String() string {
	return string(s)
}

// Normalize returns the scanner name in a normalized format (capitalized).
func (s Name) Normalize() Name {
	return Name(cases.Title(language.English).String(strings.ToLower(s.String())))
}

// Severity represents the severity level of
// a secret detected in a ConfigMap.
type Severity string

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// Int returns the integer representation of the severity.
// It maps the severity levels to integers:
// Low -> 1, Medium -> 2, High -> 3, Critical -> 4.
// If the severity is not recognized, it returns 0.
func (s Severity) Int() int {
	switch s {
	case SeverityLow:
		const low = 1
		return low
	case SeverityMedium:
		const medium = 2
		return medium
	case SeverityHigh:
		const high = 3
		return high
	case SeverityCritical:
		const critical = 4
		return critical
	default:
		const unknown = 0
		return unknown
	}
}

const (
	// UnknownSeverity indicates an unknown severity secret
	// This is the default value if no severity is specified
	// or if the severity is not recognized.
	SeverityUnknown Severity = "Unknown"
	// SeverityLow indicates a low severity secret
	SeverityLow Severity = "Low"
	// SeverityMedium indicates a medium severity secret
	SeverityMedium Severity = "Medium"
	// SeverityHigh indicates a high severity secret
	SeverityHigh Severity = "High"
	// SeverityCritical indicates a critical severity secret
	SeverityCritical Severity = "Critical"
)
