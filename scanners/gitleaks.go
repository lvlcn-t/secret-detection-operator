package scanners

import (
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// Secret is an interface for scanning text for secret values.
type Secret interface {
	// Name returns the name of the scanner.
	Name() string
	// IsSecret returns true if the given text is considered a secret value.
	IsSecret(value string) bool
}

type gitleaksScanner struct {
	detector *detect.Detector
}

func Gitleaks() (Secret, error) {
	c := config.ViperConfig{}
	cfg, err := c.Translate()
	if err != nil {
		return nil, err
	}
	return gitleaksScanner{detector: detect.NewDetector(cfg)}, nil
}

func (s gitleaksScanner) Name() string {
	return "Gitleaks"
}

func (s gitleaksScanner) IsSecret(value string) bool {
	return len(s.detector.DetectString(value)) > 0
}
