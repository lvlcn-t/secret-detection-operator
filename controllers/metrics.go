package controllers

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Defines the stages during the reconciliation process
const (
	stageLoadPolicy   = "load_policy"
	stageGetConfigMap = "get_configmap"
	stageProcessKey   = "process_key"
	stageSideEffect   = "side_effect"
	stageRemediate    = "remediate_secret"
)

var (
	// ConfigMapReconciles represents the total number of ConfigMaps reconciled
	ConfigMapReconciles = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "secret_detection_configmap_reconciles_total",
			Help: "Total number of ConfigMap reconcile loops executed",
		},
		[]string{"namespace"},
	)

	// ReconcileDuration is a histogram of reconcile durations
	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "secret_detection_reconcile_duration_seconds",
			Help:    "Duration of a ConfigMap reconcile loop",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"namespace"},
	)

	// KeysScanned is the number of keys scanned per reconciliation
	KeysScanned = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "secret_detection_keys_scanned",
			Help:    "Number of keys examined in each ConfigMap",
			Buckets: []float64{1, 5, 10, 50, 100},
		},
		[]string{"namespace"},
	)

	// SecretsDetected is the total secrets detected, labeled by severity
	SecretsDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "secret_detection_secrets_detected_total",
			Help: "Total number of secrets detected in ConfigMaps",
		},
		[]string{"namespace", "severity"},
	)

	// SecretsRemediated are the total secrets auto-remediated
	SecretsRemediated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "secret_detection_secrets_remediated_total",
			Help: "Total number of secrets automatically remediated",
		},
		[]string{"namespace"},
	)

	// ConfigMapsMutated is the total ConfigMaps mutated
	ConfigMapsMutated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "secret_detection_configmaps_mutated_total",
			Help: "Total number of ConfigMaps mutated",
		},
		[]string{"namespace"},
	)

	// ReconcileErrors are the total errors encountered during reconciliation
	ReconcileErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "secret_detection_reconcile_errors_total",
			Help: "Total number of errors encountered during reconciliation",
		},
		[]string{"namespace", "stage"},
	)
)

func init() { //nolint:gochecknoinits // Common pattern for controller-runtime
	metrics.Registry.MustRegister(
		ConfigMapReconciles,
		ReconcileDuration,
		KeysScanned,
		SecretsDetected,
		SecretsRemediated,
		ConfigMapsMutated,
		ReconcileErrors,
	)
}
