package v1alpha1

import (
	"fmt"
	"path"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ExposedSecretBuilder struct {
	*ExposedSecret
	policy *ScanPolicy
}

func NewExposedSecretBuilder(cfg *corev1.ConfigMap, exposedKey string) *ExposedSecretBuilder {
	return &ExposedSecretBuilder{
		ExposedSecret: &ExposedSecret{
			TypeMeta: metav1.TypeMeta{
				APIVersion: path.Join(APIGroup, APIVersion),
				Kind:       "ExposedSecret",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:        NewExposedSecretName(cfg, exposedKey),
				Namespace:   cfg.Namespace,
				Annotations: map[string]string{},
			},
			Spec: ExposedSecretSpec{
				Action:   DefaultAction,
				Severity: SeverityUnknown,
				Notes:    "Automatically reported by the secret-detection-operator",
			},
			Status: ExposedSecretStatus{
				ConfigMapReference: ConfigMapReference{
					Name: cfg.Name,
				},
				Key:                exposedKey,
				Scanner:            "",
				DetectedValue:      cfg.Data[exposedKey],
				Phase:              PhaseDetected,
				ObservedGeneration: cfg.Generation,
				CreatedSecretRef:   nil,
				Message:            fmt.Sprintf("Secret detected in ConfigMap %q for key %q", cfg.Name, exposedKey),
			},
		},
	}
}

func BuilderForExposedSecret(es *ExposedSecret) *ExposedSecretBuilder {
	return &ExposedSecretBuilder{
		ExposedSecret: es,
	}
}

func (b *ExposedSecretBuilder) WithPolicy(policy *ScanPolicy) *ExposedSecretBuilder {
	b.Annotations[AnnotationAppliedPolicy] = policy.Name
	b.Spec.Action = policy.Spec.Action
	b.Status.Scanner = policy.Spec.Scanner.String()
	b.policy = policy
	return b
}

func (b *ExposedSecretBuilder) WithSeverity(severity Severity) *ExposedSecretBuilder {
	b.Spec.Severity = severity
	return b
}

func (b *ExposedSecretBuilder) WithMessage(message string) *ExposedSecretBuilder {
	b.Status.Message = message
	return b
}

func (b *ExposedSecretBuilder) WithRemediated(secretName string) *ExposedSecretBuilder {
	b.Status.CreatedSecretRef = &SecretReference{Name: secretName}
	b.Status.Phase = PhaseRemediated
	return b
}

func (b *ExposedSecretBuilder) IsSeverityBelowThreshold() bool {
	if b.policy == nil {
		return false
	}
	// Only ignore if the detected severity is strictly lower than the minimum defined in policy.
	return b.Spec.Severity.Int() < b.policy.Spec.MinSeverity.Int()
}

func (b *ExposedSecretBuilder) Build() *ExposedSecret {
	b.Status.LastUpdateTime = metav1.Now()
	if b.IsSeverityBelowThreshold() {
		b.Status.Phase = PhaseIgnored
		b.Status.Message = fmt.Sprintf("Secret ignored due to policy %q", b.policy.Name)
	}
	return b.ExposedSecret
}

// NewExposedSecretName creates a new name for the ExposedSecret based on
// the ConfigMap name and the key that contains the exposed secret.
func NewExposedSecretName(cfgMap *corev1.ConfigMap, key string) string {
	return fmt.Sprintf("%s-%s", cfgMap.Name, key)
}
