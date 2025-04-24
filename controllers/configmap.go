package controllers

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
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
// +kubebuilder:rbac:groups=secretdetection.lvlcn-t.dev,resources=scanpolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=secretdetection.lvlcn-t.dev,resources=scanpolicies/status,verbs=get;update;patch

// ConfigMapReconciler scans ConfigMaps for secret values and optionally migrates them
// to a corresponding Secret and reports findings via the [v1alpha1.ExposedSecret] custom resource.
type ConfigMapReconciler struct {
	client.Client
	scheme *runtime.Scheme
}

// NewConfigMapReconciler creates a new [ConfigMapReconciler].
func NewConfigMapReconciler(c client.Client, s *runtime.Scheme) *ConfigMapReconciler {
	return &ConfigMapReconciler{Client: c, scheme: s}
}

// Reconcile scans the ConfigMap for secret-like keys and processes them according to a [v1alpha1.ScanPolicy].
// It creates or updates [v1alpha1.ExposedSecret] resources to report findings.
func (r *ConfigMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	namespace := req.Namespace
	ConfigMapReconciles.WithLabelValues(namespace).Inc()
	defer func() {
		duration := time.Since(start).Seconds()
		ReconcileDuration.WithLabelValues(namespace).Observe(duration)
	}()

	log := logr.FromContextAsSlogLogger(ctx)
	log.InfoContext(ctx, "Reconciling ConfigMap", "ConfigMap", req.NamespacedName)

	policy, err := r.loadScanPolicy(ctx, req.Namespace)
	if err != nil {
		ReconcileErrors.WithLabelValues(namespace, stageLoadPolicy).Inc()
		log.ErrorContext(ctx, "Failed to get ScanPolicy", "error", err)
		return ctrl.Result{}, err
	}

	var cfgMap corev1.ConfigMap
	if err = r.Get(ctx, req.NamespacedName, &cfgMap); err != nil {
		if !errors.IsNotFound(err) {
			ReconcileErrors.WithLabelValues(namespace, stageGetConfigMap).Inc()
		}
		log.WarnContext(ctx, "Failed to get ConfigMap", "error", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	rc := newRecCtx(r.Client, policy, &cfgMap)
	return ctrl.Result{}, rc.run(ctx)
}

// DefaultScanPolicy is the default ScanPolicy used when none is found in the namespace.
var DefaultScanPolicy = &v1alpha1.ScanPolicy{
	Spec: v1alpha1.ScanPolicySpec{
		Action:        v1alpha1.ActionReportOnly,
		MinSeverity:   v1alpha1.SeverityMedium,
		Scanner:       v1alpha1.ScannerGitleaks,
		HashAlgorithm: v1alpha1.AlgorithmSHA256,
	},
}

// loadScanPolicy retrieves the ScanPolicy for the given namespace.
// If no ScanPolicy is found, it returns a default policy.
// If multiple policies are found, it uses the first one found.
func (r *ConfigMapReconciler) loadScanPolicy(ctx context.Context, namespace string) (*v1alpha1.ScanPolicy, error) {
	log := logr.FromContextAsSlogLogger(ctx)
	var scanPolicies v1alpha1.ScanPolicyList
	if err := r.List(ctx, &scanPolicies, client.InNamespace(namespace)); err != nil {
		log.ErrorContext(ctx, "Failed to list ScanPolicies", "error", err)
		return nil, err
	}

	if len(scanPolicies.Items) == 0 {
		log.DebugContext(ctx, "No ScanPolicies found, using default values")
		return DefaultScanPolicy.DeepCopy(), nil
	}

	if len(scanPolicies.Items) > 1 {
		log.WarnContext(ctx, "Multiple ScanPolicies found, using the first one", "ScanPolicy", scanPolicies.Items[0].Name)
	}

	sp := &scanPolicies.Items[0]
	sp.Status.LastProcessedTime = metav1.Now()
	if err := r.Status().Update(ctx, sp); err != nil {
		log.ErrorContext(ctx, "Failed to update ScanPolicy status", "error", err)
	}
	return sp, nil
}

// SetupWithManager registers this reconciler with the manager.
func (r *ConfigMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Complete(r)
}
