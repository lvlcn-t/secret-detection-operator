package scanners

import (
	"testing"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
)

//go:generate go tool moq -out scanner_moq.go . Scanner
type Scanner interface {
	// Name returns the name of the scanner.
	Name() v1alpha1.ScannerName
	// IsSecret checks if the given value is a secret.
	// It returns true if the value is a secret, false otherwise.
	IsSecret(value string) bool
	// DetectSeverity analyzes the candidate secret value and returns a string representing the severity.
	// If no secret is detected, it returns an empty string.
	//
	// It uses a heuristic based on the secret’s length and Shannon entropy.
	// The severity levels are defined as follows:
	// 	- Critical: 4.5
	// 	- High: 4.0
	// 	- Medium: 3.5
	// 	- Low: < 3.5
	DetectSeverity(value string) v1alpha1.Severity
}

var _ Scanner = (*Gitleaks)(nil)

var scanners = map[v1alpha1.ScannerName]Scanner{
	v1alpha1.ScannerGitleaks: NewGitleaksScanner(),
}

// Get returns the scanner for the given name.
// If the scanner is not found, it returns nil.
func Get(name v1alpha1.ScannerName) Scanner {
	if scanner, ok := scanners[name.Normalize()]; ok {
		return scanner
	}
	return nil
}

// Set sets the scanner for the given name.
// It is used for testing purposes to inject a different scanner implementation.
func Set(t testing.TB, name v1alpha1.ScannerName, scanner Scanner) {
	t.Helper()
	scanners[name] = scanner
}
