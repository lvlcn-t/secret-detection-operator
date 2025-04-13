package scanners

import "github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"

type Scanner interface {
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
	"gitleaks": NewGitleaksScanner(),
}

// Get returns the scanner for the given name.
// If the scanner is not found, it returns nil.
func Get(name v1alpha1.ScannerName) Scanner {
	if scanner, ok := scanners[name]; ok {
		return scanner
	}
	return nil
}
