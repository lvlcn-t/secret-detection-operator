package test

import (
	"log/slog"
	"strings"

	"github.com/go-logr/logr"
	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/controllers"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const secretValue = "my-secret"

var DefaultScanner = &scanners.ScannerMock{
	NameFunc:           func() v1alpha1.ScannerName { return v1alpha1.ScannerGitleaks },
	IsSecretFunc:       func(value string) bool { return strings.Contains(value, secretValue) },
	DetectSeverityFunc: func(_ string) v1alpha1.Severity { return v1alpha1.SeverityHigh },
}

type Unittest[T TestingT] struct {
	T          T
	Client     client.Client
	client     *fake.ClientBuilder
	cfgMap     *corev1.ConfigMap
	scheme     *runtime.Scheme
	scanner    scanners.Scanner
	wantErr    bool
	assertions []func(*Unittest[T], ctrl.Result, error)
}

func (t *Unittest[T]) WithScanPolicy(policy *v1alpha1.ScanPolicy) *Unittest[T] {
	t.T.Helper()
	if policy == nil {
		return t
	}
	t.client = t.client.WithObjects(policy).WithStatusSubresource(policy)
	return t
}

func (t *Unittest[T]) WithConfigMap(cm *corev1.ConfigMap) *Unittest[T] {
	t.T.Helper()
	if cm == nil {
		return t
	}
	t.client = t.client.WithObjects(cm)
	t.cfgMap = cm
	return t
}

func (t *Unittest[T]) WithInterceptor(interceptor interceptor.Funcs) *Unittest[T] { //nolint:gocritic // performance is irrelevant when testing
	t.T.Helper()
	t.client = t.client.WithInterceptorFuncs(interceptor)
	return t
}

func (t *Unittest[T]) WithAssertion(assertion func(*Unittest[T], ctrl.Result, error)) *Unittest[T] {
	t.T.Helper()
	t.assertions = append(t.assertions, assertion)
	return t
}

func (t *Unittest[T]) WithScanner(scanner scanners.Scanner) *Unittest[T] {
	t.T.Helper()
	t.scanner = scanner
	return t
}

func (t *Unittest[T]) WantError(err bool) *Unittest[T] {
	t.T.Helper()
	t.wantErr = err
	return t
}

func (t *Unittest[T]) Run() {
	t.T.Helper()
	t.Client = t.client.Build()
	r := controllers.NewConfigMapReconciler(t.Client, t.scheme)
	ctx := logr.NewContextWithSlogLogger(t.T.Context(), slog.Default())
	if t.cfgMap == nil {
		require.Fail(t.T, "ConfigMap is required")
		return
	}
	if t.scanner != nil {
		scanners.Set(t.T, t.scanner.Name(), t.scanner)
	}

	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(t.cfgMap)}
	res, err := r.Reconcile(ctx, req)
	if (err != nil) != t.wantErr {
		t.T.Errorf("Reconcile() error = %v, wantErr %v", err, t.wantErr)
	}

	for _, assertion := range t.assertions {
		assertion(t, res, err)
	}
}
