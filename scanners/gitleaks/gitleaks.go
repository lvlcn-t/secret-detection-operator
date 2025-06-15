package gitleaks

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/go-logr/logr"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

const Name scanners.Name = "gitleaks"

var _ scanners.Scanner = (*Scanner)(nil)

type Scanner struct {
	detector *detect.Detector
}

func New(ctx context.Context, c scanners.Config) (scanners.Scanner, error) { //nolint:gocyclo // TODO: refactor this in smaller functions
	vc := config.ViperConfig{
		Extend: config.Extend{
			UseDefault: true,
		},
	}
	cfg, err := vc.Translate()
	if err != nil {
		panic(fmt.Errorf("failed to translate gitleaks config: %v", err))
	}

	if c == nil {
		return &Scanner{detector: detect.NewDetector(cfg)}, nil
	}
	conf, ok := c.(*Config)
	if !ok {
		return nil, fmt.Errorf("expected config of type *v1alpha1.GitleaksConfig, got %T", c)
	}

	log := cmp.Or(logr.FromContextAsSlogLogger(ctx), slog.Default())
	// Apply custom rules if provided
	if len(conf.Rules) > 0 {
		if cfg.Rules == nil {
			cfg.Rules = map[string]config.Rule{}
		}

		for _, rule := range conf.Rules {
			regex, compileErr := regexp.Compile(rule.Regex)
			if compileErr != nil {
				log.WarnContext(ctx, "Invalid regex in custom rule", "ruleID", rule.ID, "error", compileErr)
				continue
			}

			entropy, err := rule.Entropy.Float64()
			if err != nil {
				log.WarnContext(ctx, "Invalid entropy value in custom rule", "ruleID", rule.ID, "error", err)
				continue
			}

			gitleaksRule := config.Rule{
				RuleID:      rule.ID,
				Description: rule.Description,
				Regex:       regex,
				SecretGroup: rule.SecretGroup,
				Entropy:     entropy,
			}

			// Add keywords if provided
			if len(rule.Keywords) > 0 {
				gitleaksRule.Keywords = make([]string, len(rule.Keywords))
				copy(gitleaksRule.Keywords, rule.Keywords)
			}

			cfg.Rules[rule.ID] = gitleaksRule
			cfg.OrderedRules = append(cfg.OrderedRules, rule.ID)
		}
	}

	// Apply allowlist rules if provided
	if len(conf.Allowlist) > 0 {
		for _, allowRule := range conf.Allowlist {
			allowlist := &config.Allowlist{
				Description: allowRule.Description,
				StopWords:   allowRule.StopWords,
			}

			if allowRule.Regex != "" {
				regex, cerr := regexp.Compile(allowRule.Regex)
				if cerr != nil {
					log.WarnContext(ctx, "Invalid regex in allowlist rule", "description", allowRule.Description, "error", cerr)
					continue
				}
				allowlist.Regexes = []*regexp.Regexp{regex}
			}

			if allowRule.Path != "" {
				pathRegex, cerr := regexp.Compile(allowRule.Path)
				if cerr != nil {
					log.WarnContext(ctx, "Invalid path regex in allowlist rule", "description", allowRule.Description, "error", cerr)
					continue
				}
				allowlist.Paths = []*regexp.Regexp{pathRegex}
			}

			cfg.Allowlists = append(cfg.Allowlists, allowlist)
		}
	}

	return &Scanner{detector: detect.NewDetector(cfg)}, nil
}

// Name returns the name of the scanner.
func (g *Scanner) Name() scanners.Name {
	return Name
}

func (g *Scanner) IsSecret(value string) bool {
	return len(g.detector.DetectString(value)) > 0
}

// DetectSeverity analyzes the candidate secret value and returns a string representing the severity.
// If no secret is detected, it returns an empty string.
// It uses a heuristic based on the secret’s length and Shannon entropy.
func (g *Scanner) DetectSeverity(value string) scanners.Severity {
	findings := g.detector.DetectString(value)
	if len(findings) == 0 {
		return scanners.SeverityUnknown
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
		return scanners.SeverityCritical
	case maxEntropy > highThreshold:
		return scanners.SeverityHigh
	case maxEntropy > mediumThreshold:
		return scanners.SeverityMedium
	default:
		return scanners.SeverityLow
	}
}
