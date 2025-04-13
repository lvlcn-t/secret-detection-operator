package scanners

import (
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

type gitleaksScanner struct {
	detector *detect.Detector
}

func NewGitleaksScanner() (Secret, error) {
	c := config.ViperConfig{}
	cfg, err := c.Translate()
	if err != nil {
		return nil, err
	}
	return gitleaksScanner{detector: detect.NewDetector(cfg)}, nil
}

func (s gitleaksScanner) Name() string {
	return Gitleaks.String()
}

func (s gitleaksScanner) IsSecret(value string) bool {
	return len(s.detector.DetectString(value)) > 0
}
