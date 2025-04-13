package controllers

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-logr/logr"
	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ reconcile.Reconciler = (*ConfigMapReconciler)(nil)

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create;update;patch
// +kubebuilder:rbac:groups=secretdetection.lvlcn-t.dev,resources=exposedsecrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=secretdetection.lvlcn-t.dev,resources=exposedsecrets/status,verbs=get;update;patch

// ConfigMapReconciler scans ConfigMaps for secret values and migrates them
// to a corresponding Secret and reports findings via ExposedSecret custom resources.
type ConfigMapReconciler struct {
	client.Client
	scheme *runtime.Scheme
}

// NewConfigMapReconciler creates a new ConfigMapReconciler.
func NewConfigMapReconciler(c client.Client, s *runtime.Scheme) *ConfigMapReconciler {
	return &ConfigMapReconciler{
		Client: c,
		scheme: s,
	}
}

// Reconcile implements the controller-runtime Reconciler interface.
func (r *ConfigMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logr.FromContextAsSlogLogger(ctx)
	log.InfoContext(ctx, "Reconciling ConfigMap", "ConfigMap", req.NamespacedName)

	policy, err := r.loadScanPolicy(ctx, req.Namespace)
	if err != nil {
		log.ErrorContext(ctx, "Failed to get ScanPolicy", "error", err)
		return ctrl.Result{}, err
	}

	var cfgMap corev1.ConfigMap
	if err = r.Get(ctx, req.NamespacedName, &cfgMap); err != nil {
		log.WarnContext(ctx, "Failed to get ConfigMap", "error", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Create a ruleset based on the policy.
	ruleset := NewPolicyRuleset(policy)
	scanner := ruleset.Scanner()

	keys, found := r.getSecretKeys(scanner, &cfgMap)
	if !found {
		log.DebugContext(ctx, "No secret-like keys found in ConfigMap")
		return ctrl.Result{}, nil
	}

	for _, key := range keys {
		if slices.Contains(policy.Spec.ExcludedKeys, key) {
			log.DebugContext(ctx, "Key is excluded from scanning", "key", key)
			continue
		}

		detectedValue := cfgMap.Data[key]
		detectedSeverity := scanner.DetectSeverity(detectedValue)

		esb := v1alpha1.NewExposedSecretBuilder(&cfgMap, key).
			WithPolicy(policy).
			WithSeverity(detectedSeverity)

		// Determine the effective action.
		existingAction := esb.Spec.Action
		var effectiveAction v1alpha1.Action
		if ruleset.IsBelowSeverity(detectedSeverity) {
			log.InfoContext(ctx, "Secret severity below threshold, ignoring", "key", key, "severity", detectedSeverity)
			effectiveAction = v1alpha1.ActionIgnore
			esb = esb.WithMessage(fmt.Sprintf("Secret severity %s is below policy threshold %s", detectedSeverity, policy.Spec.MinSeverity))
		} else {
			effectiveAction = ruleset.EffectiveAction(existingAction)
		}

		// Process the secret key using the effective action.
		err = r.handleExposedSecret(ctx, policy, &cfgMap, key, esb, effectiveAction)
		if err != nil {
			log.ErrorContext(ctx, "Failed to process ExposedSecret", "error", err)
			return ctrl.Result{}, err
		}
		log.InfoContext(ctx, "Processed ExposedSecret", "key", key, "ConfigMap", cfgMap.Name)
	}

	return ctrl.Result{}, nil
}

func (r *ConfigMapReconciler) loadScanPolicy(ctx context.Context, namespace string) (*v1alpha1.ScanPolicy, error) {
	log := logr.FromContextAsSlogLogger(ctx)

	var scanPolicies v1alpha1.ScanPolicyList
	if err := r.List(ctx, &scanPolicies, client.InNamespace(namespace)); err != nil {
		log.ErrorContext(ctx, "Failed to list ScanPolicies", "error", err)
		return nil, err
	}

	if len(scanPolicies.Items) == 0 {
		log.DebugContext(ctx, "No ScanPolicies found, using default values")
		return &v1alpha1.ScanPolicy{
			Spec: v1alpha1.ScanPolicySpec{
				Action:        v1alpha1.ActionReportOnly,
				MinSeverity:   v1alpha1.SeverityMedium,
				Scanner:       v1alpha1.ScannerGitleaks,
				HashAlgorithm: v1alpha1.SHA256,
			},
		}, nil
	}

	if len(scanPolicies.Items) > 1 {
		log.WarnContext(ctx, "Multiple ScanPolicies found, using the first one", "ScanPolicy", scanPolicies.Items[0].Name)
	}
	return &scanPolicies.Items[0], nil
}

func (r *ConfigMapReconciler) getSecretKeys(scanner scanners.Scanner, cfgMap *corev1.ConfigMap) ([]string, bool) {
	var keys []string
	for key, value := range cfgMap.Data {
		if scanner.IsSecret(value) {
			keys = append(keys, key)
		}
	}
	return keys, len(keys) > 0
}

func (r *ConfigMapReconciler) handleExposedSecret(
	ctx context.Context,
	policy *v1alpha1.ScanPolicy,
	cfgMap *corev1.ConfigMap,
	key string,
	esb *v1alpha1.ExposedSecretBuilder,
	effectiveAction v1alpha1.Action,
) error {
	exposedSecretName := v1alpha1.NewExposedSecretName(cfgMap, key)
	log := logr.FromContextAsSlogLogger(ctx).With("ExposedSecret", exposedSecretName)

	// Try to get an existing ExposedSecret.
	var existing v1alpha1.ExposedSecret
	err := r.Get(ctx, client.ObjectKey{Namespace: cfgMap.Namespace, Name: exposedSecretName}, &existing)
	if err != nil && !errors.IsNotFound(err) {
		log.ErrorContext(ctx, "Failed to get ExposedSecret", "error", err)
		return fmt.Errorf("failed to get ExposedSecret: %w", err)
	}

	// If not found, create a new ExposedSecret.
	if errors.IsNotFound(err) {
		if err := r.Create(ctx, esb.Build()); err != nil {
			log.ErrorContext(ctx, "Failed to create ExposedSecret", "error", err)
			return fmt.Errorf("failed to create ExposedSecret: %w", err)
		}
		log.InfoContext(ctx, "Created ExposedSecret", "name", esb.Name)
		return nil
	}

	// For an existing object, update the policy and status.
	// (You could decide whether to update only if the severity is below threshold.)
	switch effectiveAction {
	case v1alpha1.ActionReportOnly:
		return r.handleReportOnly(ctx, esb)
	case v1alpha1.ActionAutoRemediate:
		return r.handleAutoRemediate(ctx, policy, esb, cfgMap, key)
	case v1alpha1.ActionIgnore:
		return r.handleIgnore(ctx, policy, esb)
	default:
		log.ErrorContext(ctx, "Unknown effective action", "action", effectiveAction)
		return fmt.Errorf("unknown action %q in ExposedSecret", effectiveAction)
	}
}

// handleReportOnly updates the status for ReportOnly action.
func (r *ConfigMapReconciler) handleReportOnly(ctx context.Context, esb *v1alpha1.ExposedSecretBuilder) error {
	log := logr.FromContextAsSlogLogger(ctx)
	if err := r.Status().Update(ctx, esb.Build()); err != nil {
		log.ErrorContext(ctx, "Failed to update ExposedSecret status for ReportOnly", "error", err, "ExposedSecret", esb.Name)
		return err
	}
	log.InfoContext(ctx, "Updated ExposedSecret status for ReportOnly", "ExposedSecret", esb.Name)
	return nil
}

// handleAutoRemediate creates a Secret and updates the status for AutoRemediate action.
func (r *ConfigMapReconciler) handleAutoRemediate(ctx context.Context, policy *v1alpha1.ScanPolicy, esb *v1alpha1.ExposedSecretBuilder, cfgMap *corev1.ConfigMap, key string) error {
	log := logr.FromContextAsSlogLogger(ctx)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      v1alpha1.NewExposedSecretName(cfgMap, key),
			Namespace: cfgMap.Namespace,
		},
		StringData: map[string]string{
			key: cfgMap.Data[key],
		},
	}
	if err := r.Create(ctx, secret); err != nil {
		log.ErrorContext(ctx, "Failed to create Secret for AutoRemediate", "error", err, "Secret", secret.Name)
		return err
	}
	log.InfoContext(ctx, "Created Secret for AutoRemediate", "Secret", secret.Name)

	if policy.Spec.EnableConfigMapMutation {
		remediated := cfgMap.DeepCopy()
		delete(remediated.Data, key)
		if remediated.Annotations == nil {
			remediated.Annotations = map[string]string{}
		}
		remediated.Annotations[v1alpha1.AnnotationExposedSecret] = secret.Name
		if err := r.Update(ctx, remediated); err != nil {
			log.ErrorContext(ctx, "Failed to update ConfigMap after AutoRemediate", "error", err, "ConfigMap", cfgMap.Name)
			return err
		}
		log.InfoContext(ctx, "Updated ConfigMap after AutoRemediate", "ConfigMap", cfgMap.Name)
	}

	esb = esb.WithRemediated(secret.Name)
	if err := r.Status().Update(ctx, esb.Build()); err != nil {
		log.ErrorContext(ctx, "Failed to update ExposedSecret status for AutoRemediate", "error", err, "ExposedSecret", esb.Name)
		return err
	}
	log.InfoContext(ctx, "Updated ExposedSecret status for AutoRemediate", "ExposedSecret", esb.Name)
	return nil
}

// handleIgnore updates the status for Ignore action.
func (r *ConfigMapReconciler) handleIgnore(ctx context.Context, policy *v1alpha1.ScanPolicy, esb *v1alpha1.ExposedSecretBuilder) error {
	log := logr.FromContextAsSlogLogger(ctx)
	es := v1alpha1.BuilderForExposedSecret(esb.Build()).
		WithPolicy(policy).
		WithMessage("ExposedSecret ignored by user").
		WithSeverity(esb.ExposedSecret.Spec.Severity).
		Build()
	es.Status.Phase = v1alpha1.PhaseIgnored

	if err := r.Status().Update(ctx, es); err != nil {
		log.ErrorContext(ctx, "Failed to update ExposedSecret status for Ignore", "error", err, "ExposedSecret", es.Name)
		return err
	}
	log.InfoContext(ctx, "Updated ExposedSecret status for Ignore", "ExposedSecret", es.Name)
	return nil
}

// SetupWithManager registers this reconciler with the manager.
func (r *ConfigMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Complete(r)
}
