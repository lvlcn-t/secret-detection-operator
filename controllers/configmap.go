package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

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

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create;update;patch
// +kubebuilder:rbac:groups=secretdetection.lvlcn-t.dev,resources=exposedsecrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=secretdetection.lvlcn-t.dev,resources=exposedsecrets/status,verbs=get;update;patch

// ConfigMapReconciler scans ConfigMaps for secret values and migrates them
// to a corresponding Secret and reports findings via ExposedSecret custom resources.
type ConfigMapReconciler struct {
	client.Client
	scheme  *runtime.Scheme
	scanner scanners.Secret
}

// NewConfigMapReconciler creates a new ConfigMapReconciler.
func NewConfigMapReconciler(c client.Client, s *runtime.Scheme) *ConfigMapReconciler {
	scanner, err := scanners.Gitleaks()
	if err != nil {
		panic(err)
	}
	return &ConfigMapReconciler{
		Client:  c,
		scheme:  s,
		scanner: scanner,
	}
}

// Reconcile implements the controller-runtime Reconciler interface.
func (r *ConfigMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logr.FromContextAsSlogLogger(ctx)
	log.InfoContext(ctx, "Reconciling ConfigMap", "ConfigMap", req.NamespacedName)

	var cfgMap corev1.ConfigMap
	if err := r.Get(ctx, req.NamespacedName, &cfgMap); err != nil {
		log.WarnContext(ctx, "Failed to get ConfigMap", "error", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	secretData, found := r.extractSecrets(ctx, &cfgMap)
	if !found {
		// No secrets found, so there is nothing to do.
		log.DebugContext(ctx, "No secrets found in ConfigMap", "ConfigMap", cfgMap.Name)
		return ctrl.Result{}, nil
	}

	// For each offending key, create or update an ExposedSecret resource.
	for key, value := range secretData {
		exposedSecretName := fmt.Sprintf("%s-%s", cfgMap.Name, key)
		log = log.With("ExposedSecret", exposedSecretName)

		var existing v1alpha1.ExposedSecret
		err := r.Get(ctx, client.ObjectKey{Namespace: cfgMap.Namespace, Name: exposedSecretName}, &existing)
		if err != nil && !errors.IsNotFound(err) {
			log.ErrorContext(ctx, "Failed to get ExposedSecret", "error", err)
			return ctrl.Result{}, err
		}

		if errors.IsNotFound(err) {
			newES := newExposedSecret(cfgMap, key, r, value)
			if err := r.Create(ctx, newES); err != nil {
				log.ErrorContext(ctx, "Failed to create ExposedSecret", "error", err)
				return ctrl.Result{}, err
			}
			log.InfoContext(ctx, "Created ExposedSecret")
			continue
		}

		log = log.With("Action", existing.Spec.Action)
		switch existing.Spec.Action {
		case v1alpha1.ReportOnly:
			log.DebugContext(ctx, "Updating ExposedSecret status")
			r.handleReportOnly(ctx, &existing, cfgMap, key, value)
		case v1alpha1.AutoRemediate:
			log.DebugContext(ctx, "Creating Secret and updating ExposedSecret status")
			r.handleAutoRemediate(ctx, &existing, cfgMap, key, value)
		case v1alpha1.Ignore:
			log.DebugContext(ctx, "Ignoring ExposedSecret")
			r.handleIgnore(ctx, &existing)
			continue
		default:
			log.ErrorContext(ctx, "Unknown action in ExposedSecret")
			return ctrl.Result{}, fmt.Errorf("unknown action %q in ExposedSecret", existing.Spec.Action)
		}
	}

	return ctrl.Result{}, nil
}

// prepareStatus sets common status fields.
func (r *ConfigMapReconciler) prepareStatus(es *v1alpha1.ExposedSecret, cfgMap corev1.ConfigMap, key string, value string) {
	es.Status.ConfigMapReference.Name = cfgMap.Name
	es.Status.Key = key
	es.Status.DetectedValue = r.hashSecret(value)
	es.Status.Scanner = r.scanner.Name()
	es.Status.LastUpdateTime = metav1.Now()
	es.Status.ObservedGeneration = cfgMap.GetGeneration()
}

// handleReportOnly updates the status for ReportOnly action.
func (r *ConfigMapReconciler) handleReportOnly(ctx context.Context, es *v1alpha1.ExposedSecret, cfgMap corev1.ConfigMap, key, value string) {
	log := logr.FromContextAsSlogLogger(ctx)
	r.prepareStatus(es, cfgMap, key, value)
	es.Status.Message = fmt.Sprintf("Secret detected in ConfigMap %q for key %q", cfgMap.Name, key)
	es.Status.Phase = v1alpha1.PhaseDetected
	es.Status.CreatedSecretRef = nil

	if err := r.Status().Update(ctx, es); err != nil {
		log.ErrorContext(ctx, "Failed to update ExposedSecret status for ReportOnly", "error", err, "ExposedSecret", es.Name)
		return
	}
	log.InfoContext(ctx, "Updated ExposedSecret status for ReportOnly", "ExposedSecret", es.Name)
}

// handleAutoRemediate creates a Secret and updates the status for AutoRemediate action.
func (r *ConfigMapReconciler) handleAutoRemediate(ctx context.Context, es *v1alpha1.ExposedSecret, cfgMap corev1.ConfigMap, key, value string) {
	log := logr.FromContextAsSlogLogger(ctx)
	r.prepareStatus(es, cfgMap, key, value)
	es.Status.Message = fmt.Sprintf("Secret auto-remediated from ConfigMap %q for key %q", cfgMap.Name, key)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", cfgMap.Name, key),
			Namespace: cfgMap.Namespace,
		},
		StringData: map[string]string{
			key: value,
		},
	}
	if err := r.Create(ctx, secret); err != nil {
		log.ErrorContext(ctx, "Failed to create Secret for AutoRemediate", "error", err, "Secret", secret.Name)
		return
	}
	log.InfoContext(ctx, "Created Secret for AutoRemediate", "Secret", secret.Name)
	es.Status.Phase = v1alpha1.PhaseRemediated
	es.Status.CreatedSecretRef = &v1alpha1.SecretReference{Name: secret.Name}

	if err := r.Status().Update(ctx, es); err != nil {
		log.ErrorContext(ctx, "Failed to update ExposedSecret status for AutoRemediate", "error", err, "ExposedSecret", es.Name)
		return
	}
	log.InfoContext(ctx, "Updated ExposedSecret status for AutoRemediate", "ExposedSecret", es.Name)
}

// handleIgnore updates the status for Ignore action.
func (r *ConfigMapReconciler) handleIgnore(ctx context.Context, es *v1alpha1.ExposedSecret) {
	log := logr.FromContextAsSlogLogger(ctx)
	es.Status.Phase = v1alpha1.PhaseIgnored
	es.Status.Message = "ExposedSecret ignored by user"
	es.Status.CreatedSecretRef = nil

	if err := r.Status().Update(ctx, es); err != nil {
		log.ErrorContext(ctx, "Failed to update ExposedSecret status for Ignore", "error", err, "ExposedSecret", es.Name)
		return
	}
	log.InfoContext(ctx, "Updated ExposedSecret status for Ignore", "ExposedSecret", es.Name)
}

// newExposedSecret creates a new ExposedSecret resource with common fields pre-filled.
func newExposedSecret(cfgMap corev1.ConfigMap, key string, r *ConfigMapReconciler, value string) *v1alpha1.ExposedSecret {
	es := &v1alpha1.ExposedSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", cfgMap.Name, key),
			Namespace: cfgMap.Namespace,
		},
		Spec: v1alpha1.ExposedSecretSpec{
			// Defaults to ReportOnly; users can change this later.
			Action:   v1alpha1.ReportOnly,
			Severity: v1alpha1.Medium,
			Notes:    "Automatically reported by secret-detection-operator",
		},
	}
	// Initialize status fields.
	es.Status.ConfigMapReference.Name = cfgMap.Name
	es.Status.Key = key
	es.Status.DetectedValue = r.hashSecret(value)
	es.Status.Scanner = r.scanner.Name()
	es.Status.Message = fmt.Sprintf("Secret detected in ConfigMap %q for key %q", cfgMap.Name, key)
	es.Status.Phase = v1alpha1.PhaseDetected
	es.Status.LastUpdateTime = metav1.Now()
	es.Status.ObservedGeneration = cfgMap.GetGeneration()
	return es
}

// extractSecrets scans the given ConfigMap for secret values and returns a map
// of key/value pairs along with a flag indicating whether any secrets were found.
func (r *ConfigMapReconciler) extractSecrets(ctx context.Context, cm *corev1.ConfigMap) (map[string]string, bool) {
	log := logr.FromContextAsSlogLogger(ctx)
	secretData := map[string]string{}
	found := false
	for key, value := range cm.Data {
		if r.scanner.IsSecret(value) {
			secretData[key] = value
			found = true
			log.InfoContext(ctx, "Detected secret value in ConfigMap", "ConfigMap", cm.ObjectMeta.Name, "key", key)
		}
	}
	return secretData, found
}

// hashSecret hashes the secret value using SHA-256 and prefixes the result with "sha256:".
func (r *ConfigMapReconciler) hashSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(hash[:])
}

// SetupWithManager registers this reconciler with the manager.
func (r *ConfigMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Complete(r)
}
