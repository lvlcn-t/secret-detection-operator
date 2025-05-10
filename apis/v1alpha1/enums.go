package v1alpha1

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
)

// Action represents the action to take when
// a secret is detected in a ConfigMap.
type Action string

// String returns the string representation of the action.
func (a Action) String() string {
	return string(a)
}

const (
	// ActionReportOnly indicates that the secret should be reported but not remediated
	ActionReportOnly Action = "ReportOnly"
	// ActionAutoRemediate indicates that the secret should be remediated automatically
	ActionAutoRemediate Action = "AutoRemediate"
	// ActionIgnore indicates that the secret should be ignored
	ActionIgnore Action = "Ignore"

	// DefaultAction is the default action to take when a secret is detected.
	DefaultAction Action = ActionReportOnly
)

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

// Phase represents the current phase of an
// ExposedSecret in the reconciliation process.
type Phase string

// String returns the string representation of the phase.
func (p Phase) String() string {
	return string(p)
}

const (
	// PhaseDetected means the secret was found but not acted upon yet
	PhaseDetected Phase = "Detected"
	// PhaseRemediated means the secret was moved to a Secret
	PhaseRemediated Phase = "Remediated"
	// PhaseIgnored means the finding was explicitly ignored
	PhaseIgnored Phase = "Ignored"
)

// ScannerName represents the name of a secret scanner.
type ScannerName string

// String returns the string representation of the scanner name.
func (s ScannerName) String() string {
	return string(s)
}

const (
	// ScannerGitleaks is the name of the ScannerGitleaks scanner.
	ScannerGitleaks ScannerName = "Gitleaks"
)

// HashAlgorithm represents the hashing algorithm
// used to hash the reported detected exposed secret value.
type HashAlgorithm string

// String returns the string representation of the hashing algorithm.
func (ha HashAlgorithm) String() string {
	return string(ha)
}

const (
	// AlgorithmNone is the no hashing algorithm.
	AlgorithmNone HashAlgorithm = "none"
	// AlgorithmSHA256 is the SHA-256 hashing algorithm.
	AlgorithmSHA256 HashAlgorithm = "sha256"
	// AlgorithmSHA512 is the SHA-512 hashing algorithm.
	AlgorithmSHA512 HashAlgorithm = "sha512"
)

// Hash hashes the given secret value using the hashing algorithm.
// It returns the hashed value as a string prefixed with the algorithm name.
func (ha HashAlgorithm) Hash(secret string) string {
	switch ha {
	case AlgorithmNone:
		return base64.StdEncoding.EncodeToString([]byte(secret))
	case AlgorithmSHA256:
		hash := sha256.Sum256([]byte(secret))
		return "sha256:" + hex.EncodeToString(hash[:])
	case AlgorithmSHA512:
		hash := sha512.Sum512([]byte(secret))
		return "sha512:" + hex.EncodeToString(hash[:])
	default:
		return "<unsupported>"
	}
}
