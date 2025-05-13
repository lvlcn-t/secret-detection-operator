package controllers

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"

	"github.com/go-logr/logr"
	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// recCtx holds the context and dependencies needed to reconcile a single [corev1.ConfigMap].
type recCtx struct {
	// ctx is the context for the reconciliation.
	ctx context.Context
	// cl is the Kubernetes client used to interact with the cluster.
	cl client.Client
	// scanner is the secret scanner used to detect secrets in the [corev1.ConfigMap].
	scanner scanners.Scanner
	// policy is the policy policy derived from the [v1alpha1.ScanPolicy].
	policy *v1alpha1.ScanPolicy
	// configMap is the [corev1.ConfigMap] being reconciled.
	configMap *corev1.ConfigMap

	// log is the logger used for logging messages during reconciliation.
	log *slog.Logger
}

// newRecCtx creates a new [recCtx] for a given [v1alpha1.ScanPolicy] and [corev1.ConfigMap].
func newRecCtx(c client.Client, policy *v1alpha1.ScanPolicy, cm *corev1.ConfigMap) *recCtx {
	rc := &recCtx{
		cl:        c,
		policy:    policy,
		scanner:   scanners.Get(policy.Spec.Scanner),
		configMap: cm,
	}
	return rc
}

// run executes the reconciliation for the ConfigMap: it scans for secret-like keys,
// filters excluded keys, and processes each remaining key according to policy.
func (rc *recCtx) run(ctx context.Context) error {
	rc.ctx = ctx
	rc.log = logr.FromContextAsSlogLogger(ctx).With("ConfigMap", rc.configMap.Name)

	keys := rc.findSecretKeys()
	KeysScanned.WithLabelValues(rc.configMap.Namespace).Observe(float64(len(rc.configMap.Data)))
	if len(keys) == 0 {
		rc.log.DebugContext(ctx, "No secret-like data keys found")
		return nil
	}

	for _, key := range keys {
		if slices.Contains(rc.policy.Spec.ExcludedKeys, key) {
			rc.log.DebugContext(ctx, "Key excluded from scanning", "key", key)
			continue
		}

		if err := rc.process(key); err != nil {
			ReconcileErrors.WithLabelValues(rc.configMap.Namespace, stageProcessKey).Inc()
			rc.log.ErrorContext(ctx, "Failed to process key", "key", key, "error", err)
			return err
		}
		rc.log.DebugContext(ctx, "Processed key", "key", key)
	}
	return nil
}

// process handles a single ConfigMap key: it builds an ExposedSecret, creates it if missing,
// resolves the effective action, and dispatches to the appropriate handler.
func (rc *recCtx) process(key string) error {
	value := rc.configMap.Data[key]
	sev := rc.scanner.DetectSeverity(value)

	existing := v1alpha1.ExposedSecret{Spec: v1alpha1.ExposedSecretSpec{Action: v1alpha1.DefaultAction}}
	err := rc.cl.Get(rc.ctx, client.ObjectKey{Namespace: rc.configMap.Namespace, Name: v1alpha1.NewExposedSecretName(rc.configMap, key)}, &existing)
	if err != nil && !errors.IsNotFound(err) {
		rc.log.ErrorContext(rc.ctx, "Failed to get ExposedSecret", "error", err)
		return fmt.Errorf("failed to get ExposedSecret: %w", err)
	}

	builder := v1alpha1.NewExposedSecretBuilder(rc.configMap, key).
		WithPolicy(rc.policy).
		WithExisting(&existing).
		WithSeverity(sev)

	res := rc.computeResolvedAction(builder, sev)
	rc.log.DebugContext(rc.ctx, "Resolved action",
		"action", res.Action, "severity", res.FinalSeverity,
		"phase", res.FinalPhase, "message", res.Message)
	SecretsDetected.WithLabelValues(rc.configMap.Namespace, string(res.FinalSeverity)).Inc()

	builder = builder.
		WithAction(res.Action).
		WithMessage(res.Message).
		WithPhase(res.FinalPhase).
		WithSeverity(res.FinalSeverity)

	if err = rc.doSideEffects(res, builder, key); err != nil {
		ReconcileErrors.WithLabelValues(rc.configMap.Namespace, stageSideEffect).Inc()
		rc.log.ErrorContext(rc.ctx, "Failed to do side effects", "error", err)
		return fmt.Errorf("failed to do side effects: %w", err)
	}

	es := builder.Build()
	if err = rc.createOrUpdate(es); err != nil {
		rc.log.ErrorContext(rc.ctx, "Failed to create or update ExposedSecret", "error", err)
		return fmt.Errorf("failed to create or update ExposedSecret: %w", err)
	}
	rc.log.DebugContext(rc.ctx, "Created or updated ExposedSecret")
	return nil
}

// doSideEffects performs any side effects required by the resolved action.
// This function mutates the provided ExposedSecretBuilder in place to reflect
// the changes caused by the side effects (e.g., remediation).
func (rc *recCtx) doSideEffects(res ResolvedAction, builder *v1alpha1.ExposedSecretBuilder, key string) error {
	if res.Action == v1alpha1.ActionAutoRemediate {
		secret, rErr := rc.doRemediation(builder, key)
		if rErr != nil {
			ReconcileErrors.WithLabelValues(rc.configMap.Namespace, stageRemediate).Inc()
			rc.log.ErrorContext(rc.ctx, "Failed to do remediation", "error", rErr)
			return fmt.Errorf("failed to do remediation: %w", rErr)
		}
		builder.WithRemediated(secret)
	}

	return nil
}

func (rc *recCtx) computeResolvedAction(b *v1alpha1.ExposedSecretBuilder, sev v1alpha1.Severity) ResolvedAction {
	res := ActionResolver{
		OverrideAction: b.ExistingAction(),
		HasOverride:    b.Override(),
		DefaultPolicy:  rc.policy.Spec.Action,
		Severity:       sev,
		MinSeverity:    rc.policy.Spec.MinSeverity,
	}
	return res.Resolve()
}

func (rc *recCtx) doRemediation(b *v1alpha1.ExposedSecretBuilder, key string) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: b.Name, Namespace: rc.configMap.Namespace},
		StringData: map[string]string{key: rc.configMap.Data[key]},
	}
	if err := rc.createOrUpdate(secret); err != nil {
		rc.log.ErrorContext(rc.ctx, "Failed to create or update Secret", "error", err)
		return nil, fmt.Errorf("failed to create or update Secret: %w", err)
	}
	rc.log.InfoContext(rc.ctx, "Secret created")
	SecretsRemediated.WithLabelValues(rc.configMap.Namespace).Inc()

	if rc.policy.Spec.EnableConfigMapMutation {
		if err := rc.autoRemediateConfigMap(secret, key); err != nil {
			rc.log.ErrorContext(rc.ctx, "Failed to update ConfigMap", "error", err)
			return nil, fmt.Errorf("failed to update ConfigMap: %w", err)
		}
		rc.log.InfoContext(rc.ctx, "Auto-remediated ConfigMap", "key", key)
		ConfigMapsMutated.WithLabelValues(rc.configMap.Namespace).Inc()
	}
	return secret, nil
}

// findSecretKeys returns all keys in the ConfigMap whose values match the scanner's secret pattern.
func (rc *recCtx) findSecretKeys() []string {
	var keys []string
	for key, value := range rc.configMap.Data {
		if rc.scanner.IsSecret(value) {
			keys = append(keys, key)
		}
	}
	return keys
}

// autoRemediateConfigMap removes the secret key from the ConfigMap, annotates it,
// and updates the ConfigMap resource in the cluster.
func (rc *recCtx) autoRemediateConfigMap(secret *corev1.Secret, key string) error {
	rem := rc.configMap.DeepCopy()
	if rem.Annotations == nil {
		rem.Annotations = map[string]string{}
	}
	rem.Annotations[v1alpha1.AnnotationExposedSecret] = secret.Name
	delete(rem.Data, key)

	if err := rc.cl.Update(rc.ctx, rem); err != nil {
		return err
	}
	return nil
}

// createOrUpdate creates or updates the given object in the cluster.
func (rc *recCtx) createOrUpdate(obj client.Object) error {
	if obj == nil {
		return stderrors.New("object is nil")
	}

	// We use reflection here to avoid allocating an unnecessary deep copy of the object.
	t := reflect.TypeOf(obj)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	existing := reflect.New(t).Interface().(client.Object)
	if err := rc.cl.Get(rc.ctx, client.ObjectKeyFromObject(obj), existing); err != nil {
		if errors.IsNotFound(err) {
			return rc.cl.Create(rc.ctx, obj)
		}
		return err
	}

	// Preserve the resource version to ensure the update is applied correctly.
	obj.SetResourceVersion(existing.GetResourceVersion())
	return rc.cl.Update(rc.ctx, obj)
}
