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
	ctrl "sigs.k8s.io/controller-runtime"
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
	// ruleset is the policy ruleset derived from the [v1alpha1.ScanPolicy].
	ruleset *ruleset
	// configMap is the [corev1.ConfigMap] being reconciled.
	configMap *corev1.ConfigMap

	// log is the logger used for logging messages during reconciliation.
	log *slog.Logger
	// handlers is a map of actions to their corresponding handler functions.
	handlers map[v1alpha1.Action]func(b *v1alpha1.ExposedSecretBuilder, key string) error
}

// newRecCtx creates a new [recCtx] for a given [v1alpha1.ScanPolicy] and [corev1.ConfigMap].
func newRecCtx(client client.Client, policy *v1alpha1.ScanPolicy, cm *corev1.ConfigMap) *recCtx {
	ruleset := newPolicyRuleset(policy)
	rc := &recCtx{
		cl:        client,
		ruleset:   ruleset,
		scanner:   ruleset.Scanner(),
		configMap: cm,
	}
	rc.handlers = map[v1alpha1.Action]func(b *v1alpha1.ExposedSecretBuilder, key string) error{
		v1alpha1.ActionReportOnly:    rc.handleReportOnly,
		v1alpha1.ActionAutoRemediate: rc.handleAutoRemediate,
		v1alpha1.ActionIgnore:        rc.handleIgnore,
	}
	return rc
}

// run executes the reconciliation for the ConfigMap: it scans for secret-like keys,
// filters excluded keys, and processes each remaining key according to policy.
func (rc *recCtx) run(ctx context.Context) (ctrl.Result, error) {
	rc.ctx = ctx
	rc.log = logr.FromContextAsSlogLogger(ctx).With("ConfigMap", rc.configMap.Name)

	keys := rc.findSecretKeys()
	if len(keys) == 0 {
		rc.log.DebugContext(ctx, "No secret-like data keys found")
		return ctrl.Result{}, nil
	}

	for _, key := range keys {
		if slices.Contains(rc.ruleset.policy.Spec.ExcludedKeys, key) {
			rc.log.DebugContext(ctx, "Key excluded from scanning", "key", key)
			continue
		}

		if err := rc.process(key); err != nil {
			rc.log.ErrorContext(ctx, "Failed to process key", "key", key, "error", err)
			return ctrl.Result{}, err
		}
		rc.log.DebugContext(ctx, "Processed key", "key", key)
	}
	return ctrl.Result{}, nil
}

// process handles a single ConfigMap key: it builds an ExposedSecret, creates it if missing,
// resolves the effective action, and dispatches to the appropriate handler.
func (rc *recCtx) process(key string) error {
	value := rc.configMap.Data[key]
	sev := rc.scanner.DetectSeverity(value)

	builder := v1alpha1.NewExposedSecretBuilder(rc.configMap, key).
		WithPolicy(rc.ruleset.policy).
		WithSeverity(sev)

	action := rc.resolveAction(builder, sev)
	handler := rc.handlers[action]
	return handler(builder, key)
}

// handleReportOnly updates the status of the ExposedSecret to reflect a report-only action.
func (rc *recCtx) handleReportOnly(b *v1alpha1.ExposedSecretBuilder, _ string) error {
	log := rc.log.With("ExposedSecret", b.Name, "action", b.Spec.Action)
	es := b.Build()
	if err := createOrUpdate(rc.ctx, rc.cl, es); err != nil {
		log.ErrorContext(rc.ctx, "Failed to create or update ExposedSecret", "error", err)
		return fmt.Errorf("failed to create or update ExposedSecret: %w", err)
	}
	log.DebugContext(rc.ctx, "Created or updated ExposedSecret")
	return nil
}

// handleAutoRemediate creates a Kubernetes Secret for the exposed value, optionally
// mutates the ConfigMap to remove the secret, and updates the ExposedSecret status.
func (rc *recCtx) handleAutoRemediate(b *v1alpha1.ExposedSecretBuilder, key string) error {
	log := rc.log.With("ExposedSecret", b.Name, "action", b.Spec.Action, "Secret", b.Name)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.Name,
			Namespace: rc.configMap.Namespace,
		},
		StringData: map[string]string{
			key: rc.configMap.Data[key],
		},
	}
	if err := createOrUpdate(rc.ctx, rc.cl, secret); err != nil {
		log.ErrorContext(rc.ctx, "Failed to create or update Secret", "error", err)
		return fmt.Errorf("failed to create or update Secret: %w", err)
	}
	rc.log.InfoContext(rc.ctx, "Secret created")

	if rc.ruleset.policy.Spec.EnableConfigMapMutation {
		if err := rc.autoRemediateConfigMap(secret, key); err != nil {
			rc.log.ErrorContext(rc.ctx, "Failed to update ConfigMap", "error", err)
			return fmt.Errorf("failed to update ConfigMap: %w", err)
		}
		rc.log.InfoContext(rc.ctx, "Auto-remediated ConfigMap", "key", key)
	}

	es := b.WithRemediated(secret).Build()
	if err := createOrUpdate(rc.ctx, rc.cl, es); err != nil {
		log.ErrorContext(rc.ctx, "Failed to create or update ExposedSecret", "error", err)
		return fmt.Errorf("failed to create or update ExposedSecret: %w", err)
	}
	log.DebugContext(rc.ctx, "Created or updated with remediation")
	return nil
}

// handleIgnore updates the ExposedSecret status to mark the finding as ignored.
func (rc *recCtx) handleIgnore(b *v1alpha1.ExposedSecretBuilder, _ string) error {
	log := rc.log.With("ExposedSecret", b.Name, "action", b.Spec.Action)
	es := b.WithMessage("ExposedSecret ignored by policy").Build()
	es.Status.Phase = v1alpha1.PhaseIgnored

	if err := createOrUpdate(rc.ctx, rc.cl, es); err != nil {
		log.ErrorContext(rc.ctx, "Failed to create or update ExposedSecret", "error", err)
		return fmt.Errorf("failed to create or update ExposedSecret: %w", err)
	}
	log.DebugContext(rc.ctx, "Updated status with ignore message")
	return nil
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

// resolveAction computes the effective action for a secret based on policy severity threshold
// and any existing builder state, updating the builder message if severity is too low.
func (rc *recCtx) resolveAction(b *v1alpha1.ExposedSecretBuilder, sev v1alpha1.Severity) v1alpha1.Action {
	if rc.ruleset.IsBelowSeverity(sev) {
		b.WithMessage(fmt.Sprintf("Secret severity %q below policy threshold %q", sev, rc.ruleset.policy.Spec.MinSeverity))
		return v1alpha1.ActionIgnore
	}

	return rc.ruleset.EffectiveAction(b.Spec.Action)
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
func createOrUpdate(ctx context.Context, cl client.Client, obj client.Object) error {
	if obj == nil {
		return stderrors.New("object is nil")
	}

	// We use reflection here to avoid allocating an unnecessary deep copy of the object.
	t := reflect.TypeOf(obj)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	existing := reflect.New(t).Interface().(client.Object)
	if err := cl.Get(ctx, client.ObjectKeyFromObject(obj), existing); err != nil {
		if errors.IsNotFound(err) {
			return cl.Create(ctx, obj)
		}
		return err
	}

	// Preserve the resource version to ensure the update is applied correctly.
	obj.SetResourceVersion(existing.GetResourceVersion())
	return cl.Update(ctx, obj)
}
