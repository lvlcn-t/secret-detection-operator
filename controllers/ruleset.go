package controllers

import (
	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
)

// PolicyRuleset encapsulates decision-making logic for applying a ScanPolicy.
type PolicyRuleset struct {
	policy *v1alpha1.ScanPolicy
}

// NewPolicyRuleset creates a new ruleset from the ScanPolicy.
func NewPolicyRuleset(policy *v1alpha1.ScanPolicy) *PolicyRuleset {
	return &PolicyRuleset{policy: policy}
}

// EffectiveAction returns the action to take. If the secret’s action is still the default,
// then it uses the policy’s action; otherwise, it uses the action already set.
func (ps *PolicyRuleset) EffectiveAction(existing v1alpha1.Action) v1alpha1.Action {
	if existing == v1alpha1.DefaultAction {
		return ps.policy.Spec.Action
	}
	return existing
}

// Scanner returns the scanner to use for this policy.
// Defaults to the gitleaks scanner if not set.
func (ps *PolicyRuleset) Scanner() scanners.Scanner {
	if ps.policy == nil {
		return scanners.Get(v1alpha1.ScannerGitleaks)
	}
	return scanners.Get(ps.policy.Spec.Scanner)
}

// IsBelowSeverity returns true if the detected secret severity is strictly lower than
// the policy threshold.
func (ps *PolicyRuleset) IsBelowSeverity(detectedSeverity v1alpha1.Severity) bool {
	return detectedSeverity.Int() < ps.policy.Spec.MinSeverity.Int()
}
