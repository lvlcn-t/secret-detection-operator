package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConfigMapReference is a reference to a ConfigMap that contains the secret value.
type ConfigMapReference struct {
	// Name of the referenced ConfigMap
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// SecretReference is a reference to a Secret that contains the secret value.
// This is used when the secret is remediated and a new Secret is created.
type SecretReference struct {
	// Name of the referenced Secret
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// ExposedSecretSpec defines user intent and desired handling behavior
type ExposedSecretSpec struct {
	// Action defines the desired response: "ReportOnly", "AutoRemediate", "Ignore"
	// +kubebuilder:validation:Enum=ReportOnly;AutoRemediate;Ignore
	// +kubebuilder:default=ReportOnly
	Action Action `json:"action,omitempty"`

	// Severity indicates how serious the secret exposure is
	// +kubebuilder:validation:Enum=Unknown;Low;Medium;High;Critical
	// +kubebuilder:default=Medium
	Severity Severity `json:"severity,omitempty"`

	// Notes are free-form text the user can provide
	Notes string `json:"notes,omitempty"`
}

// +k8s:deepcopy-gen=true
// ExposedSecretStatus defines the observed state of ExposedSecret
type ExposedSecretStatus struct {
	// ConfigMapRef is the ConfigMap where the secret was found.
	ConfigMapReference ConfigMapReference `json:"configMapRef"`

	// Key is the key inside the ConfigMap that was identified.
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`

	// Scanner indicates the tool that detected the secret.
	Scanner ScannerName `json:"scanner,omitempty"`

	// DetectedValue is the found secret value as a hash.
	DetectedValue string `json:"detectedValue,omitempty"`

	// CreatedSecretRef points to the Secret created to store the migrated key/value.
	// This will only be set if the action is "AutoRemediate".
	CreatedSecretRef *SecretReference `json:"createdSecretRef,omitempty"`

	// Phase is the current status: "Detected", "Remediated", "Ignored"
	// +kubebuilder:validation:Enum=Detected;Remediated;Ignored
	Phase Phase `json:"phase,omitempty"`

	// Message provides additional details about the status.
	Message string `json:"message,omitempty"`

	// LastUpdateTime is the time the status was last updated.
	LastUpdateTime metav1.Time `json:"lastUpdateTime,omitempty"`

	// ObservedGeneration is the last generation seen by the controller
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=exs,scope=Namespaced

// ExposedSecret is the Schema for the exposedsecrets API
type ExposedSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExposedSecretSpec   `json:"spec,omitempty"`
	Status ExposedSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ExposedSecretList contains a list of ExposedSecret.
type ExposedSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExposedSecret `json:"items"`
}
