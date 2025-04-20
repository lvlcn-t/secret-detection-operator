package controllers_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/controllers"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
)

// secretValue is the secret value used in tests.
const secretValue = "my-secret"

// mockScanner is a mock implementation of the Scanner interface.
var mockScanner = &scanners.ScannerMock{
	IsSecretFunc: func(value string) bool {
		return value == secretValue
	},
	DetectSeverityFunc: func(value string) v1alpha1.Severity {
		return v1alpha1.SeverityHigh
	},
}

// errorListClient simulates a List failure when loading ScanPolicies.
type errorListClient struct{ ctrlclient.Client }

func (e *errorListClient) List(ctx context.Context, list ctrlclient.ObjectList, opts ...ctrlclient.ListOption) error {
	return errors.New("simulated list error")
}

func TestReconcile_ScanPolicyListError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	errClient := &errorListClient{fake.NewClientBuilder().WithScheme(scheme).Build()}
	reconciler := controllers.NewConfigMapReconciler(errClient, scheme)

	req := ctrl.Request{NamespacedName: ctrlclient.ObjectKey{Namespace: "secret-detection-system", Name: "cm"}}
	_, err := reconciler.Reconcile(newCtx(t), req)
	require.Error(t, err, "expected error when listing ScanPolicies")
}

func TestReconcile_ReportOnly(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	tests := []struct {
		name        string
		scanner     scanners.Scanner
		existingCM  *corev1.ConfigMap
		wantExposed bool
		wantKeys    []string
	}{
		{
			name:        "no secret-like data",
			scanner:     scanners.Get(v1alpha1.ScannerGitleaks),
			existingCM:  &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm1"}, Data: map[string]string{"foo": "bar"}},
			wantExposed: false,
		},
		{
			name:    "secret-like data triggers ExposedSecret",
			scanner: mockScanner,
			existingCM: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm2"},
				Data:       map[string]string{"password": secretValue},
			},
			wantExposed: true,
			wantKeys:    []string{"password"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newFakeClient(t, scheme, tt.existingCM)
			r := controllers.NewConfigMapReconciler(client, scheme)
			req := ctrl.Request{NamespacedName: ctrlclient.ObjectKey{Namespace: tt.existingCM.Namespace, Name: tt.existingCM.Name}}
			scanners.Set(t, v1alpha1.ScannerGitleaks, tt.scanner)

			_, err := r.Reconcile(newCtx(t), req)
			require.NoError(t, err)

			list := &v1alpha1.ExposedSecretList{}
			require.NoError(t, client.List(context.Background(), list))
			if tt.wantExposed {
				require.Len(t, list.Items, 1, "should have created one ExposedSecret")
				for _, es := range list.Items {
					require.Contains(t, tt.wantKeys, es.Status.Key)
					require.Equal(t, v1alpha1.PhaseDetected, es.Status.Phase)
				}
			} else {
				require.Empty(t, list.Items, "no ExposedSecrets should exist")
			}
		})
	}
}

func TestReconcile_AutoRemediate(t *testing.T) { //nolint:funlen // It's a table driven test, they get long.
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	baseCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "auto-cm"},
		Data:       map[string]string{"secret": secretValue},
	}
	policy := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "example-policy"},
		Spec: v1alpha1.ScanPolicySpec{
			Action:                  v1alpha1.ActionAutoRemediate,
			MinSeverity:             v1alpha1.SeverityLow,
			EnableConfigMapMutation: true,
			Scanner:                 v1alpha1.ScannerGitleaks,
			HashAlgorithm:           v1alpha1.SHA256,
		},
	}

	tests := []struct {
		name           string
		enableMutation bool
		wantAnnotation bool
	}{
		{
			name:           "mutation enabled",
			enableMutation: true,
			wantAnnotation: true,
		},
		{
			name:           "mutation disabled",
			enableMutation: false,
			wantAnnotation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := policy.DeepCopy()
			sp.Spec.EnableConfigMapMutation = tt.enableMutation

			client := newFakeClient(t, scheme, baseCM, sp)
			r := controllers.NewConfigMapReconciler(client, scheme)
			req := ctrl.Request{NamespacedName: ctrlclient.ObjectKey{Namespace: "secret-detection-system", Name: "auto-cm"}}
			scanners.Set(t, v1alpha1.ScannerGitleaks, mockScanner)

			_, err := r.Reconcile(newCtx(t), req)
			require.NoError(t, err)

			secrets := &corev1.SecretList{}
			require.NoError(t, client.List(context.Background(), secrets))
			require.Len(t, secrets.Items, 1)
			require.Equal(t, v1alpha1.NewExposedSecretName(baseCM, "secret"), secrets.Items[0].Name, "secret name should match CM-key pattern")

			if tt.enableMutation {
				cm := &corev1.ConfigMap{}
				require.NoError(t, client.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "secret-detection-system", Name: "auto-cm"}, cm))
				_, has := cm.Annotations[v1alpha1.AnnotationExposedSecret]
				require.Equal(t, tt.wantAnnotation, has)
			}
		})
	}
}

func TestReconcile_ExcludedKeys(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "example-cm"},
		Data:       map[string]string{"skipme": secretValue},
	}
	policy := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "example-policy"},
		Spec: v1alpha1.ScanPolicySpec{
			Action:       v1alpha1.ActionReportOnly,
			MinSeverity:  v1alpha1.SeverityLow,
			Scanner:      v1alpha1.ScannerGitleaks,
			ExcludedKeys: []string{"skipme"},
		},
	}
	client := newFakeClient(t, scheme, cm, policy)
	r := controllers.NewConfigMapReconciler(client, scheme)
	req := ctrl.Request{NamespacedName: ctrlclient.ObjectKey{Namespace: "secret-detection-system", Name: "example-cm"}}
	scanners.Set(t, v1alpha1.ScannerGitleaks, mockScanner)

	_, err := r.Reconcile(newCtx(t), req)
	require.NoError(t, err)

	list := &v1alpha1.ExposedSecretList{}
	require.NoError(t, client.List(context.Background(), list))
	require.Empty(t, list.Items, "excluded key should not produce ExposedSecret")
}

// newFakeClient creates a new fake client with the given objects and scheme.
func newFakeClient(t *testing.T, scheme *runtime.Scheme, objs ...ctrlclient.Object) ctrlclient.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// newCtx creates a new context with a logger for testing.
func newCtx(t *testing.T) context.Context {
	t.Helper()
	return logr.NewContextWithSlogLogger(t.Context(), slog.Default())
}
