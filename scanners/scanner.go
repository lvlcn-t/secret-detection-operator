package scanners

// Secret is an interface for scanning text for secret values.
type Secret interface {
	// Name returns the name of the scanner.
	Name() string
	// IsSecret returns true if the given text is considered a secret value.
	IsSecret(value string) bool
}

// Scanner is a string type that represents the name of a scanner.
type Scanner string

// String returns the string representation of the scanner.
func (s Scanner) String() string {
	return string(s)
}

const (
	// Gitleaks is the name of the Gitleaks scanner.
	Gitleaks Scanner = "Gitleaks"
)
