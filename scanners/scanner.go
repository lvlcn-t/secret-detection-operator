package scanners

import (
	"context"
)

//go:generate go tool moq -out scanner_moq.go . Scanner
type Scanner interface {
	// Name returns the name of the scanner.
	Name() Name
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
	DetectSeverity(value string) Severity
}

type Config interface {
	// Scanner returns a scanner instance configured with the provided settings.
	// It should return an error if the configuration is invalid or if the scanner cannot be created.
	// Due to import cycle issues, the caller must ensure that the scanner implements the [scanners.Scanner] interface.
	Scanner(ctx context.Context) (Scanner, error)
}
