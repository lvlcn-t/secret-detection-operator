//go:build e2e

package e2e_test

import (
	"testing"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
	"github.com/lvlcn-t/secret-detection-operator/scanners/gitleaks"
	"github.com/lvlcn-t/secret-detection-operator/test"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const detectedValue = "ghp_" + "1234567890abcdef1234567890abcdef12345678"

func TestE2E_DetectSecret_ReportOnly(t *testing.T) {
	e2e := test.NewFramework(t).E2E(t)
	ctx := t.Context()
	ns := e2e.AddNamespace("")

	policy := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: ns.Name},
		Spec: v1alpha1.ScanPolicySpec{
			Action:        v1alpha1.ActionReportOnly,
			MinSeverity:   scanners.SeverityLow,
			Scanner:       gitleaks.Name,
			HashAlgorithm: v1alpha1.AlgorithmSHA256,
		},
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: ns.Name},
		Data:       map[string]string{"password": detectedValue},
	}

	e2e.
		WithScanPolicy(policy).
		WithConfigMap(cm).
		WithAssertion(func(e *test.E2E) {
			es, err := e.WaitForExposedSecretPhase(ctx, ns.Name, "cm-password", v1alpha1.PhaseDetected)
			require.NoError(t, err)
			require.Equal(t, v1alpha1.ActionReportOnly, es.Spec.Action)
			require.Equal(t, v1alpha1.PhaseDetected, es.Status.Phase)
			require.Equal(t, v1alpha1.AlgorithmSHA256.Hash(detectedValue), es.Status.DetectedValue)
			require.Equal(t, "cm", es.Status.ConfigMapReference.Name)
			require.Equal(t, "password", es.Status.Key)
			require.Equal(t, gitleaks.Name, es.Status.Scanner)
		}).
		Run()
}

func TestE2E_AutoRemediate(t *testing.T) {
	e2e := test.NewFramework(t).E2E(t)
	ctx := t.Context()
	ns := e2e.AddNamespace("")

	policy := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: ns.Name},
		Spec: v1alpha1.ScanPolicySpec{
			Action:                  v1alpha1.ActionAutoRemediate,
			MinSeverity:             scanners.SeverityLow,
			Scanner:                 gitleaks.Name,
			HashAlgorithm:           v1alpha1.AlgorithmSHA256,
			EnableConfigMapMutation: true,
		},
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: ns.Name},
		Data:       map[string]string{"password": detectedValue},
	}

	e2e.
		WithScanPolicy(policy).
		WithConfigMap(cm).
		WithAssertion(func(e *test.E2E) {
			es, err := e.WaitForExposedSecretPhase(ctx, ns.Name, "cm-password", v1alpha1.PhaseRemediated)
			require.NoError(t, err)
			require.Equal(t, v1alpha1.ActionAutoRemediate, es.Spec.Action)
			require.NotNil(t, es.Status.CreatedSecretRef)
			require.Equal(t, "cm-password", es.Status.CreatedSecretRef.Name)
		}).
		WithAssertion(func(e *test.E2E) {
			secret, err := e.WaitForSecret(ctx, ns.Name, "cm-password")
			require.NoError(t, err)
			require.Equal(t, detectedValue, string(secret.Data["password"]))
		}).
		WithAssertion(func(e *test.E2E) {
			updatedCM, err := e.WaitForConfigMapKeyAbsent(ctx, ns.Name, "cm", "password")
			require.NoError(t, err)
			require.Equal(t, "cm-password", updatedCM.Annotations[v1alpha1.AnnotationExposedSecret])
		}).
		Run()
}

func TestE2E_ScanPolicyScoping(t *testing.T) {
	e2e := test.NewFramework(t).E2E(t)
	ctx := t.Context()
	nsWithPolicy := e2e.AddNamespace("with-policy")
	nsWithoutPolicy := e2e.AddNamespace("without-policy")

	policy := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: nsWithPolicy.Name},
		Spec: v1alpha1.ScanPolicySpec{
			Action:        v1alpha1.ActionIgnore,
			MinSeverity:   scanners.SeverityLow,
			Scanner:       gitleaks.Name,
			HashAlgorithm: v1alpha1.AlgorithmSHA256,
		},
	}

	cmWithPolicy := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: nsWithPolicy.Name},
		Data:       map[string]string{"password": detectedValue},
	}

	cmWithoutPolicy := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: nsWithoutPolicy.Name},
		Data:       map[string]string{"password": detectedValue},
	}

	e2e.
		WithScanPolicy(policy).
		WithConfigMap(cmWithPolicy).
		WithConfigMap(cmWithoutPolicy).
		WithAssertion(func(e *test.E2E) {
			esIgnored, err := e.WaitForExposedSecretPhase(ctx, nsWithPolicy.Name, "cm-password", v1alpha1.PhaseIgnored)
			require.NoError(t, err)
			require.Equal(t, v1alpha1.ActionIgnore, esIgnored.Spec.Action)
		}).
		WithAssertion(func(e *test.E2E) {
			esDetected, err := e.WaitForExposedSecretPhase(ctx, nsWithoutPolicy.Name, "cm-password", v1alpha1.PhaseDetected)
			require.NoError(t, err)
			require.Equal(t, v1alpha1.ActionReportOnly, esDetected.Spec.Action)
		}).
		Run()
}

func TestE2E_IgnoredViaPolicy(t *testing.T) {
	e2e := test.NewFramework(t).E2E(t)
	ctx := t.Context()
	ns := e2e.AddNamespace("")

	policy := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: ns.Name},
		Spec: v1alpha1.ScanPolicySpec{
			Action:        v1alpha1.ActionIgnore,
			MinSeverity:   scanners.SeverityLow,
			Scanner:       gitleaks.Name,
			HashAlgorithm: v1alpha1.AlgorithmSHA256,
		},
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: ns.Name},
		Data:       map[string]string{"password": detectedValue},
	}

	e2e.
		WithScanPolicy(policy).
		WithConfigMap(cm).
		WithAssertion(func(e *test.E2E) {
			es, err := e.WaitForExposedSecretPhase(ctx, ns.Name, "cm-password", v1alpha1.PhaseIgnored)
			require.NoError(t, err)
			require.Equal(t, v1alpha1.ActionIgnore, es.Spec.Action)
			require.Equal(t, v1alpha1.PhaseIgnored, es.Status.Phase)
			require.Equal(t, scanners.SeverityUnknown, es.Spec.Severity)
		}).
		WithAssertion(func(e *test.E2E) {
			secret := &corev1.Secret{}
			err := e.Client.Get(ctx, types.NamespacedName{Namespace: ns.Name, Name: "cm-password"}, secret)
			require.Error(t, err)
			require.True(t, apierrors.IsNotFound(err))
		}).
		Run()
}
