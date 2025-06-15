package gitleaks

import (
	"context"
	"strconv"

	"github.com/lvlcn-t/secret-detection-operator/scanners"
)

var _ scanners.Config = (*Config)(nil)

// +kubebuilder:object:generate=true

// Config defines custom configuration for the Gitleaks scanner.
type Config struct {
	// UseDefault indicates whether to extend the default Gitleaks configuration.
	// When true, custom rules are added to the default rules.
	// When false, only the custom rules are used.
	// +kubebuilder:default=true
	UseDefault bool `json:"useDefault,omitempty"`

	// Rules defines custom secret detection rules.
	// Each rule specifies patterns and thresholds for detecting specific types of secrets.
	// +optional
	Rules []Rule `json:"rules,omitempty"`

	// Allowlist defines patterns that should be ignored during scanning.
	// This can be used to exclude known false positives.
	// +optional
	Allowlist []AllowlistRule `json:"allowlist,omitempty"`
}

func (c *Config) Scanner(ctx context.Context) (scanners.Scanner, error) {
	return New(ctx, c)
}

type Entropy string

func (e Entropy) Float64() (float64, error) {
	return strconv.ParseFloat(string(e), 64)
}

// Rule defines a custom rule for detecting secrets.
type Rule struct {
	// ID is a unique identifier for this rule.
	// +kubebuilder:validation:Required
	ID string `json:"id"`

	// Description provides a human-readable description of what this rule detects.
	// +optional
	Description string `json:"description,omitempty"`

	// Regex is the regular expression pattern used to detect secrets.
	// The pattern should contain a capture group for the secret value.
	// +kubebuilder:validation:Required
	Regex string `json:"regex"`

	// SecretGroup specifies which regex capture group contains the secret.
	// Defaults to 0 (entire match) if not specified.
	// +kubebuilder:default=0
	SecretGroup int `json:"secretGroup,omitempty"`

	// Entropy specifies the minimum Shannon entropy required for a match to be considered a secret.
	// Higher values reduce false positives but may miss some secrets.
	// Typical values range from 3.0 to 4.5.
	// +optional
	Entropy Entropy `json:"entropy,omitempty"`

	// Keywords defines additional keywords that must be present near the secret for detection.
	// This can help reduce false positives by requiring context.
	// +optional
	Keywords []string `json:"keywords,omitempty"`
}

// AllowlistRule defines a pattern that should be ignored during scanning.
type AllowlistRule struct {
	// Description provides a human-readable description of what this allowlist rule excludes.
	// +optional
	Description string `json:"description,omitempty"`

	// Regex is a regular expression pattern that matches content to be ignored.
	// +optional
	Regex string `json:"regex,omitempty"`

	// Path is a file path pattern that should be ignored.
	// +optional
	Path string `json:"path,omitempty"`

	// StopWords are specific strings that should be ignored.
	// +optional
	StopWords []string `json:"stopWords,omitempty"`
}
