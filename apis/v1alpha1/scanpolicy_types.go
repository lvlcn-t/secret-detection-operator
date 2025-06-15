package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScanPolicySpec defines namespace-specific scanning configuration
type ScanPolicySpec struct {
	// Action defines the default remediation behavior for newly detected secrets.
	// +kubebuilder:validation:Enum=ReportOnly;AutoRemediate;Ignore
	// +kubebuilder:default=ReportOnly
	Action Action `json:"action,omitempty"`

	// MinSeverity defines the lowest severity that triggers action.
	// Secrets with lower severity will be ignored.
	// +kubebuilder:validation:Enum=Low;Medium;High;Critical
	// +kubebuilder:default=Medium
	MinSeverity Severity `json:"minSeverity,omitempty"`

	// ExcludedKeys defines a list of ConfigMap keys to ignore during scanning.
	// This allows safe-listing non-sensitive values that may otherwise trigger false positives.
	// +optional
	ExcludedKeys []string `json:"excludedKeys,omitempty"`

	// EnableConfigMapMutation allows the operator to delete secret-like keys from ConfigMaps.
	// +kubebuilder:default=false
	EnableConfigMapMutation bool `json:"enableConfigMapMutation,omitempty"`

	// Scanner defines which detection engine to use for identifying secrets.
	// +kubebuilder:validation:Enum=Gitleaks
	// +kubebuilder:default=Gitleaks
	Scanner ScannerName `json:"scanner,omitempty"`

	// HashAlgorithm defines how secret values are hashed before reporting.
	// +kubebuilder:validation:Enum=none;sha256;sha512
	// +kubebuilder:default=none
	HashAlgorithm HashAlgorithm `json:"hashAlgorithm,omitempty"`
}

// ScanPolicyStatus reflects observed configuration behavior or health.
type ScanPolicyStatus struct {
	// ObservedGeneration is the most recent generation observed by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastProcessedTime is the last time this config was used during reconciliation.
	LastProcessedTime metav1.Time `json:"lastProcessedTime,omitempty"`

	// Message provides insight into the status of the config.
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sdc,scope=Namespaced

// ScanPolicy defines namespace-specific configuration for the operator
type ScanPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScanPolicySpec   `json:"spec,omitempty"`
	Status ScanPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ScanPolicyList contains a list of SecretDetectionConfig
type ScanPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanPolicy `json:"items"`
}
