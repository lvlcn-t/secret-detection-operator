package scanners

import (
	"fmt"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

type Gitleaks struct {
	detector *detect.Detector
}

func NewGitleaksScanner() *Gitleaks {
	c := config.ViperConfig{
		Extend: config.Extend{
			UseDefault: true,
		},
	}
	cfg, err := c.Translate()
	if err != nil {
		panic(fmt.Errorf("failed to translate gitleaks config: %v", err))
	}
	return &Gitleaks{detector: detect.NewDetector(cfg)}
}

// Name returns the name of the scanner.
func (g *Gitleaks) Name() v1alpha1.ScannerName {
	return v1alpha1.ScannerGitleaks
}

func (g *Gitleaks) IsSecret(value string) bool {
	return len(g.detector.DetectString(value)) > 0
}

// DetectSeverity analyzes the candidate secret value and returns a string representing the severity.
// If no secret is detected, it returns an empty string.
// It uses a heuristic based on the secret’s length and Shannon entropy.
func (g *Gitleaks) DetectSeverity(value string) v1alpha1.Severity {
	findings := g.detector.DetectString(value)
	if len(findings) == 0 {
		return v1alpha1.SeverityUnknown
	}

	// Select the maximum entropy among all findings.
	var maxEntropy float32
	for i := range findings {
		if findings[i].Entropy > maxEntropy {
			maxEntropy = findings[i].Entropy
		}
	}

	// Entropy thresholds for severity levels.
	const (
		criticalThreshold = 4.5
		highThreshold     = 4.0
		mediumThreshold   = 3.5
	)
	switch {
	case maxEntropy > criticalThreshold:
		return v1alpha1.SeverityCritical
	case maxEntropy > highThreshold:
		return v1alpha1.SeverityHigh
	case maxEntropy > mediumThreshold:
		return v1alpha1.SeverityMedium
	default:
		return v1alpha1.SeverityLow
	}
}
