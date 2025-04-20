package controllers

import (
	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
)

// ruleset encapsulates decision-making logic for applying a [v1alpha1.ScanPolicy].
type ruleset struct {
	// policy is the [v1alpha1.ScanPolicy] used to determine the action to take.
	policy *v1alpha1.ScanPolicy
}

// newPolicyRuleset creates a new ruleset from the ScanPolicy.
func newPolicyRuleset(policy *v1alpha1.ScanPolicy) *ruleset {
	return &ruleset{policy: policy}
}

// EffectiveAction returns the action to take. If the secret’s action is still the default,
// then it uses the policy’s action; otherwise, it uses the action already set.
func (rs *ruleset) EffectiveAction(existing v1alpha1.Action) v1alpha1.Action {
	effective := rs.policy.Spec.Action
	if rs.policy == nil {
		effective = v1alpha1.DefaultAction
	}

	if existing == v1alpha1.DefaultAction {
		return effective
	}
	return existing
}

// Scanner returns the scanner to use for this policy.
// Defaults to the gitleaks scanner if not set.
func (rs *ruleset) Scanner() scanners.Scanner {
	if rs.policy == nil {
		return scanners.Get(v1alpha1.ScannerGitleaks)
	}

	return scanners.Get(rs.policy.Spec.Scanner)
}

// IsBelowSeverity returns true if the detected secret severity is strictly lower than
// the policy threshold.
func (rs *ruleset) IsBelowSeverity(detectedSeverity v1alpha1.Severity) bool {
	if rs.policy == nil {
		return false
	}

	return detectedSeverity.Int() < rs.policy.Spec.MinSeverity.Int()
}
