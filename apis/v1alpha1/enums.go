package v1alpha1

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"

	"github.com/lvlcn-t/secret-detection-operator/scanners"
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
type Severity = scanners.Severity

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
type ScannerName = scanners.Name

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
