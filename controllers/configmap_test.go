package controllers_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
	"github.com/lvlcn-t/secret-detection-operator/scanners/gitleaks"
	"github.com/lvlcn-t/secret-detection-operator/test"
)

const secretValue = "my-secret"

// TestReconcile_ScanPolicyListError verifies that listing policies errors out.
func TestReconcile_ScanPolicyListError(t *testing.T) {
	test.NewFramework(t).Unit(t).
		WithInterceptor(interceptor.Funcs{
			List: func(ctx context.Context, client ctrlclient.WithWatch, list ctrlclient.ObjectList, opts ...ctrlclient.ListOption) error {
				if _, ok := list.(*v1alpha1.ScanPolicyList); ok {
					return errors.New("simulated list error")
				}
				return client.List(ctx, list, opts...)
			},
		}).
		WithScanPolicy(&v1alpha1.ScanPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pol"},
			Spec:       v1alpha1.ScanPolicySpec{Action: v1alpha1.ActionAutoRemediate, MinSeverity: scanners.SeverityLow, Scanner: gitleaks.Name},
		}).
		WithConfigMap(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm"},
			Data:       map[string]string{"k": secretValue},
		}).
		WantError(true).
		WithAssertion(func(u *test.Unittest, r ctrl.Result, err error) {
			require.Error(t, err)
			require.Equal(t, ctrl.Result{}, r)
		}).
		Run()
}

func TestReconcile(t *testing.T) {
	fw := test.NewFramework(t)
	tests := []struct {
		name   string
		cm     *corev1.ConfigMap
		policy *v1alpha1.ScanPolicy
		want   *v1alpha1.ExposedSecret
	}{
		{
			name: "no secret-like data",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "cm0"},
				Data:       map[string]string{"foo": "bar"},
			},
			want: nil,
		},
		{
			name: "detects secret - ignore key",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "cm1"},
				Data:       map[string]string{"password": secretValue},
			},
			policy: &v1alpha1.ScanPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "pol"},
				Spec: v1alpha1.ScanPolicySpec{
					Action:        v1alpha1.ActionIgnore,
					MinSeverity:   test.DefaultScanner.DetectSeverity(secretValue),
					Scanner:       test.DefaultScanner.Name(),
					HashAlgorithm: v1alpha1.AlgorithmSHA256,
					ExcludedKeys:  []string{"password"},
				},
			},
			want: nil,
		},
		{
			name: "detects secret - report only",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "cm2"},
				Data:       map[string]string{"password": secretValue},
			},
			want: &v1alpha1.ExposedSecret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "cm2-password"},
				Spec: v1alpha1.ExposedSecretSpec{
					Action:   v1alpha1.ActionReportOnly,
					Severity: test.DefaultScanner.DetectSeverity(secretValue),
				},
				Status: v1alpha1.ExposedSecretStatus{
					ConfigMapReference: v1alpha1.ConfigMapReference{Name: "cm2"},
					Key:                "password",
					Scanner:            test.DefaultScanner.Name(),
					DetectedValue:      v1alpha1.AlgorithmSHA256.Hash(secretValue),
					Phase:              v1alpha1.PhaseDetected,
				},
			},
		},
		{
			name: "detects secret - ignore policy",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "cm3"},
				Data:       map[string]string{"password": secretValue},
			},
			policy: &v1alpha1.ScanPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "pol"},
				Spec: v1alpha1.ScanPolicySpec{
					Action:        v1alpha1.ActionIgnore,
					MinSeverity:   test.DefaultScanner.DetectSeverity(secretValue),
					Scanner:       test.DefaultScanner.Name(),
					HashAlgorithm: v1alpha1.AlgorithmSHA256,
				},
			},
			want: &v1alpha1.ExposedSecret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "cm3-password"},
				Spec: v1alpha1.ExposedSecretSpec{
					Action:   v1alpha1.ActionIgnore,
					Severity: scanners.SeverityUnknown,
				},
				Status: v1alpha1.ExposedSecretStatus{
					ConfigMapReference: v1alpha1.ConfigMapReference{Name: "cm3"},
					Key:                "password",
					Scanner:            test.DefaultScanner.Name(),
					DetectedValue:      v1alpha1.AlgorithmSHA256.Hash(secretValue),
					Phase:              v1alpha1.PhaseIgnored,
				},
			},
		},
		{
			name: "detects secret - report only - severity below threshold",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "cm4"},
				Data:       map[string]string{"password": secretValue},
			},
			policy: &v1alpha1.ScanPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "pol"},
				Spec: v1alpha1.ScanPolicySpec{
					Action:        v1alpha1.ActionReportOnly,
					MinSeverity:   scanners.SeverityCritical,
					Scanner:       test.DefaultScanner.Name(),
					HashAlgorithm: v1alpha1.AlgorithmSHA256,
				},
			},
			want: &v1alpha1.ExposedSecret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "cm4-password"},
				Spec: v1alpha1.ExposedSecretSpec{
					Action:   v1alpha1.ActionIgnore,
					Severity: scanners.SeverityUnknown,
				},
				Status: v1alpha1.ExposedSecretStatus{
					ConfigMapReference: v1alpha1.ConfigMapReference{Name: "cm4"},
					Key:                "password",
					Scanner:            test.DefaultScanner.Name(),
					DetectedValue:      v1alpha1.AlgorithmSHA256.Hash(secretValue),
					Phase:              v1alpha1.PhaseIgnored,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw.Unit(t).
				WithConfigMap(tt.cm).
				WithScanPolicy(tt.policy).
				WithScanner(test.DefaultScanner).
				WantError(false).
				WithAssertion(func(u *test.Unittest, r ctrl.Result, err error) {
					list := &v1alpha1.ExposedSecretList{}
					require.NoError(t, u.Client.List(u.T.Context(), list))
					if tt.want == nil {
						require.Empty(t, list.Items)
						return
					}
					require.Len(t, list.Items, 1)
					got := list.Items[0]
					test.AssertMatchesNonZeroFields(t, *tt.want, got)
				}).
				Run()
		})
	}
}

func TestReconcile_AutoRemediate(t *testing.T) {
	fw := test.NewFramework(t)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm"},
		Data:       map[string]string{"k": secretValue},
	}
	pol := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pol"},
		Spec: v1alpha1.ScanPolicySpec{
			Action:        v1alpha1.ActionAutoRemediate,
			MinSeverity:   scanners.SeverityLow,
			Scanner:       gitleaks.Name,
			HashAlgorithm: v1alpha1.AlgorithmSHA256,
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm-k"},
		StringData: map[string]string{"k": secretValue},
	}
	es := &v1alpha1.ExposedSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm-k"},
		Spec: v1alpha1.ExposedSecretSpec{
			Action:   v1alpha1.ActionAutoRemediate,
			Severity: test.DefaultScanner.DetectSeverity(secretValue),
		},
		Status: v1alpha1.ExposedSecretStatus{
			ConfigMapReference: v1alpha1.ConfigMapReference{Name: "cm"},
			Key:                "k",
			Scanner:            test.DefaultScanner.Name(),
			DetectedValue:      v1alpha1.AlgorithmSHA256.Hash(secretValue),
			Phase:              v1alpha1.PhaseRemediated,
			CreatedSecretRef:   &v1alpha1.SecretReference{Name: "cm-k"},
		},
	}

	fw.Unit(t).
		WithConfigMap(cm).
		WithScanPolicy(pol).
		WithScanner(test.DefaultScanner).
		WantError(false).
		WithAssertion(func(u *test.Unittest, r ctrl.Result, err error) {
			secList := &corev1.SecretList{}
			require.NoError(t, u.Client.List(u.T.Context(), secList))
			require.Len(t, secList.Items, 1)
			test.AssertMatchesNonZeroFields(t, *secret, secList.Items[0])
		}).
		WithAssertion(func(u *test.Unittest, r ctrl.Result, err error) {
			exList := &v1alpha1.ExposedSecretList{}
			require.NoError(t, u.Client.List(u.T.Context(), exList))
			require.Len(t, exList.Items, 1)
			test.AssertMatchesNonZeroFields(t, *es, exList.Items[0])
		}).
		Run()
}

func TestReconcile_MultipleScanPolicies(t *testing.T) {
	fw := test.NewFramework(t)

	// ConfigMap with one secret‑like key
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm"},
		Data:       map[string]string{"k": secretValue},
	}

	// First policy will ignore the exposed secret (audit only)
	polA := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "first"},
		Spec: v1alpha1.ScanPolicySpec{
			Action:        v1alpha1.ActionIgnore,
			MinSeverity:   test.DefaultScanner.DetectSeverity(secretValue),
			Scanner:       test.DefaultScanner.Name(),
			HashAlgorithm: v1alpha1.AlgorithmSHA256,
		},
	}
	// Second policy would auto‑remediate if it were chosen
	polB := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "second"},
		Spec: v1alpha1.ScanPolicySpec{
			Action:        v1alpha1.ActionAutoRemediate,
			MinSeverity:   scanners.SeverityLow,
			Scanner:       test.DefaultScanner.Name(),
			HashAlgorithm: v1alpha1.AlgorithmSHA256,
		},
	}

	fw.Unit(t).
		WithConfigMap(cm).
		WithInterceptor(interceptor.Funcs{
			List: func(ctx context.Context, c ctrlclient.WithWatch, list ctrlclient.ObjectList, opts ...ctrlclient.ListOption) error {
				if lp, ok := list.(*v1alpha1.ScanPolicyList); ok {
					lp.Items = []v1alpha1.ScanPolicy{*polA, *polB}
					return nil
				}
				return c.List(ctx, list, opts...)
			},
		}).
		WithScanner(test.DefaultScanner).
		WantError(false).
		WithAssertion(func(u *test.Unittest, _ ctrl.Result, err error) {
			list := &v1alpha1.ExposedSecretList{}
			require.NoError(t, u.Client.List(u.T.Context(), list))
			require.Len(t, list.Items, 1)
			test.AssertMatchesNonZeroFields(t, v1alpha1.ExposedSecret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm-k"},
				Spec: v1alpha1.ExposedSecretSpec{
					Action:   v1alpha1.ActionIgnore,
					Severity: scanners.SeverityUnknown,
				},
				Status: v1alpha1.ExposedSecretStatus{
					ConfigMapReference: v1alpha1.ConfigMapReference{Name: "cm"},
					Key:                "k",
					Scanner:            test.DefaultScanner.Name(),
					DetectedValue:      v1alpha1.AlgorithmSHA256.Hash(secretValue),
					Phase:              v1alpha1.PhaseIgnored,
				},
			}, list.Items[0])
		}).
		Run()
}

func TestReconcile_MultipleSecretKeys_ReportOnly(t *testing.T) {
	fw := test.NewFramework(t)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "secret-detection-system", Name: "cm"},
		Data: map[string]string{
			"k1": secretValue,
			"k2": secretValue,
		},
	}

	fw.Unit(t).
		WithConfigMap(cm).
		WithScanner(test.DefaultScanner).
		WantError(false).
		WithAssertion(func(u *test.Unittest, _ ctrl.Result, err error) {
			require.NoError(t, err)
			list := &v1alpha1.ExposedSecretList{}
			require.NoError(t, u.Client.List(u.T.Context(), list))
			require.Len(t, list.Items, 2)

			names := map[string]struct{}{}
			for _, es := range list.Items {
				names[es.Name] = struct{}{}
				require.Equal(t, v1alpha1.PhaseDetected, es.Status.Phase)
				require.Equal(t, test.DefaultScanner.Name(), es.Status.Scanner)
			}
			require.Contains(t, names, "cm-k1")
			require.Contains(t, names, "cm-k2")
		}).
		Run()
}

func TestReconcile_AutoRemediate_WithConfigMapMutation(t *testing.T) {
	fw := test.NewFramework(t)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm"},
		Data:       map[string]string{"k": secretValue},
	}
	pol := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pol"},
		Spec: v1alpha1.ScanPolicySpec{
			Action:                  v1alpha1.ActionAutoRemediate,
			MinSeverity:             scanners.SeverityLow,
			Scanner:                 test.DefaultScanner.Name(),
			HashAlgorithm:           v1alpha1.AlgorithmSHA256,
			EnableConfigMapMutation: true,
		},
	}

	fw.Unit(t).
		WithConfigMap(cm).
		WithScanPolicy(pol).
		WithScanner(test.DefaultScanner).
		WantError(false).
		WithAssertion(func(u *test.Unittest, _ ctrl.Result, err error) {
			require.NoError(t, err)
			secList := &corev1.SecretList{}
			require.NoError(t, u.Client.List(u.T.Context(), secList))
			require.Len(t, secList.Items, 1)
			require.Equal(t, "cm-k", secList.Items[0].Name)
		}).
		WithAssertion(func(u *test.Unittest, _ ctrl.Result, err error) {
			var updated corev1.ConfigMap
			require.NoError(t, u.Client.Get(
				u.T.Context(),
				ctrlclient.ObjectKey{Namespace: "ns", Name: "cm"},
				&updated,
			))
			require.NotContains(t, updated.Data, "k")
			require.Equal(t,
				"cm-k",
				updated.Annotations[v1alpha1.AnnotationExposedSecret],
			)
		}).
		Run()
}

func TestReconcile_AutoRemediate_MultipleKeys(t *testing.T) {
	fw := test.NewFramework(t)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm"},
		Data: map[string]string{
			"k1": secretValue,
			"k2": secretValue,
		},
	}
	pol := &v1alpha1.ScanPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pol"},
		Spec: v1alpha1.ScanPolicySpec{
			Action:        v1alpha1.ActionAutoRemediate,
			MinSeverity:   scanners.SeverityLow,
			Scanner:       test.DefaultScanner.Name(),
			HashAlgorithm: v1alpha1.AlgorithmSHA256,
		},
	}

	fw.Unit(t).
		WithConfigMap(cm).
		WithScanPolicy(pol).
		WithScanner(test.DefaultScanner).
		WantError(false).
		WithAssertion(func(u *test.Unittest, _ ctrl.Result, err error) {
			require.NoError(t, err)
			secList := &corev1.SecretList{}
			require.NoError(t, u.Client.List(u.T.Context(), secList))
			require.Len(t, secList.Items, 2)

			names := map[string]struct{}{}
			for _, s := range secList.Items {
				names[s.Name] = struct{}{}
			}
			require.Contains(t, names, "cm-k1")
			require.Contains(t, names, "cm-k2")
		}).
		WithAssertion(func(u *test.Unittest, _ ctrl.Result, err error) {
			exList := &v1alpha1.ExposedSecretList{}
			require.NoError(t, u.Client.List(u.T.Context(), exList))
			require.Len(t, exList.Items, 2)

			names := map[string]struct{}{}
			for _, ex := range exList.Items {
				names[ex.Name] = struct{}{}
				require.Equal(t, v1alpha1.PhaseRemediated, ex.Status.Phase)
			}
			require.Contains(t, names, "cm-k1")
			require.Contains(t, names, "cm-k2")
		}).
		Run()
}
