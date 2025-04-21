package v1alpha1

import (
	"fmt"
	"path"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ExposedSecretBuilder struct {
	*ExposedSecret

	// existingAction defines if the resource already existed, pin down its user‑chosen action
	existingAction Action
	// override is true if the user actually set that action (vs leaving it at the policy default)
	override bool

	policy   *ScanPolicy
	severity Severity
	hashAlgo HashAlgorithm
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
				ConfigMapReference: ConfigMapReference{Name: cfg.Name},
				Key:                exposedKey,
				Scanner:            "",
				DetectedValue:      cfg.Data[exposedKey],
				Phase:              PhaseDetected,
				ObservedGeneration: cfg.Generation,
				CreatedSecretRef:   nil,
				Message:            fmt.Sprintf("Secret detected in ConfigMap %q for key %q", cfg.Name, exposedKey),
			},
		},
		hashAlgo: AlgorithmSHA256,
	}
}

func (b *ExposedSecretBuilder) ExistingAction() Action {
	return b.existingAction
}

func (b *ExposedSecretBuilder) Override() bool {
	return b.override
}

func (b *ExposedSecretBuilder) WithAction(act Action) *ExposedSecretBuilder {
	b.Spec.Action = act
	return b
}

func (b *ExposedSecretBuilder) WithPhase(phase Phase) *ExposedSecretBuilder {
	b.Status.Phase = phase
	return b
}

func (b *ExposedSecretBuilder) WithPolicy(policy *ScanPolicy) *ExposedSecretBuilder {
	b.policy = policy
	b.Annotations[AnnotationAppliedPolicy] = policy.Name
	b.Status.Scanner = policy.Spec.Scanner.String()
	b.hashAlgo = policy.Spec.HashAlgorithm
	return b
}

func (b *ExposedSecretBuilder) WithExisting(es *ExposedSecret) *ExposedSecretBuilder {
	if es.Spec.Action != DefaultAction {
		b.existingAction = es.Spec.Action
		b.override = true
	}
	b.Spec.Notes = es.Spec.Notes
	return b
}

func (b *ExposedSecretBuilder) WithSeverity(s Severity) *ExposedSecretBuilder {
	b.severity = s
	b.Spec.Severity = s
	return b
}

func (b *ExposedSecretBuilder) WithMessage(message string) *ExposedSecretBuilder {
	b.Status.Message = message
	return b
}

func (b *ExposedSecretBuilder) WithRemediated(secret *corev1.Secret) *ExposedSecretBuilder {
	b.Status.CreatedSecretRef = &SecretReference{Name: secret.Name}
	b.Spec.Action = ActionAutoRemediate
	b.Status.Phase = PhaseRemediated
	return b
}

func (b *ExposedSecretBuilder) Build() *ExposedSecret {
	b.Status.LastUpdateTime = metav1.Now()
	b.Status.DetectedValue = b.hashAlgo.Hash(b.Status.DetectedValue)
	return b.ExposedSecret
}

// NewExposedSecretName creates a new name for the ExposedSecret based on
// the ConfigMap name and the key that contains the exposed secret.
func NewExposedSecretName(cfgMap *corev1.ConfigMap, key string) string {
	return fmt.Sprintf("%s-%s", cfgMap.Name, key)
}
