package controllers

import (
	"fmt"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
)

// ActionResolver decides "policy vs user vs severity”
type ActionResolver struct {
	OverrideAction v1alpha1.Action
	HasOverride    bool
	DefaultPolicy  v1alpha1.Action
	Severity       v1alpha1.Severity
	MinSeverity    v1alpha1.Severity
}

type ResolvedAction struct {
	Action        v1alpha1.Action
	FinalPhase    v1alpha1.Phase
	FinalSeverity v1alpha1.Severity
	Message       string
}

func (r ActionResolver) Resolve() ResolvedAction {
	if r.HasOverride {
		return ResolvedAction{
			Action:        r.OverrideAction,
			FinalPhase:    v1alpha1.PhaseDetected,
			FinalSeverity: r.Severity,
			Message:       "user override",
		}
	}

	if r.Severity.Int() < r.MinSeverity.Int() {
		return ResolvedAction{
			Action:        v1alpha1.ActionIgnore,
			FinalPhase:    v1alpha1.PhaseIgnored,
			FinalSeverity: v1alpha1.SeverityUnknown,
			Message:       fmt.Sprintf("Severity %q below %q", r.Severity, r.MinSeverity),
		}
	}

	switch r.DefaultPolicy {
	case v1alpha1.ActionIgnore:
		return ResolvedAction{Action: v1alpha1.ActionIgnore, FinalPhase: v1alpha1.PhaseIgnored, FinalSeverity: v1alpha1.SeverityUnknown, Message: "ignored by policy"}
	case v1alpha1.ActionReportOnly:
		return ResolvedAction{Action: v1alpha1.ActionReportOnly, FinalPhase: v1alpha1.PhaseDetected, FinalSeverity: r.Severity, Message: "reported only"}
	case v1alpha1.ActionAutoRemediate:
		return ResolvedAction{Action: v1alpha1.ActionAutoRemediate, FinalPhase: v1alpha1.PhaseDetected, FinalSeverity: r.Severity, Message: "auto-remediation"}
	default:
		panic(fmt.Errorf("policy action %q is not recognized; this shouldn't have happened. If you see this, please report a bug", r.DefaultPolicy))
	}
}
