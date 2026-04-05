package test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	e2ePollInterval = time.Second
	e2eWaitTimeout  = time.Minute
)

type E2E struct {
	T          testing.TB
	Client     client.Client
	namespaces []*corev1.Namespace
	scanPolicy []*v1alpha1.ScanPolicy
	configMaps []*corev1.ConfigMap
	assertions []func(*E2E)
}

func (e *E2E) AddNamespace(prefix string) *corev1.Namespace {
	e.T.Helper()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespaceNameFromTest(e.T, prefix)},
	}
	e.namespaces = append(e.namespaces, ns)
	return ns
}

func (e *E2E) WithScanPolicy(policy *v1alpha1.ScanPolicy) *E2E {
	e.T.Helper()
	if policy == nil {
		return e
	}
	e.scanPolicy = append(e.scanPolicy, policy)
	return e
}

func (e *E2E) WithConfigMap(cm *corev1.ConfigMap) *E2E {
	e.T.Helper()
	if cm == nil {
		return e
	}
	e.configMaps = append(e.configMaps, cm)
	return e
}

func (e *E2E) WithAssertion(assertion func(*E2E)) *E2E {
	e.T.Helper()
	e.assertions = append(e.assertions, assertion)
	return e
}

func (e *E2E) Run() {
	e.T.Helper()

	for _, ns := range e.namespaces {
		require.NoError(e.T, e.Client.Create(e.T.Context(), ns))
		nsCopy := ns.DeepCopy()
		e.T.Cleanup(func() {
			_ = e.Client.Delete(context.Background(), nsCopy)
		})
	}

	for _, policy := range e.scanPolicy {
		require.NoError(e.T, e.Client.Create(e.T.Context(), policy))
	}

	for _, cm := range e.configMaps {
		require.NoError(e.T, e.Client.Create(e.T.Context(), cm))
	}

	for _, assertion := range e.assertions {
		assertion(e)
	}
}

func (e *E2E) WaitForExposedSecretPhase(ctx context.Context, namespace, name string, phase v1alpha1.Phase) (*v1alpha1.ExposedSecret, error) {
	e.T.Helper()
	obj := &v1alpha1.ExposedSecret{}
	err := wait.PollUntilContextTimeout(ctx, e2ePollInterval, e2eWaitTimeout, true, func(ctx context.Context) (bool, error) {
		err := e.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, obj)
		if err != nil {
			return false, client.IgnoreNotFound(err)
		}
		return obj.Status.Phase == phase, nil
	})
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (e *E2E) WaitForSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	e.T.Helper()
	obj := &corev1.Secret{}
	err := wait.PollUntilContextTimeout(ctx, e2ePollInterval, e2eWaitTimeout, true, func(ctx context.Context) (bool, error) {
		err := e.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, obj)
		if err != nil {
			return false, client.IgnoreNotFound(err)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (e *E2E) WaitForConfigMapKeyAbsent(ctx context.Context, namespace, name, key string) (*corev1.ConfigMap, error) {
	e.T.Helper()
	obj := &corev1.ConfigMap{}
	err := wait.PollUntilContextTimeout(ctx, e2ePollInterval, e2eWaitTimeout, true, func(ctx context.Context) (bool, error) {
		err := e.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, obj)
		if err != nil {
			return false, err
		}
		_, exists := obj.Data[key]
		return !exists, nil
	})
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func namespaceNameFromTest(t testing.TB, prefix string) string {
	t.Helper()
	const suffixSize = 4
	base := strings.ToLower(strings.TrimSpace(prefix))
	if base == "" {
		base = strings.ToLower(t.Name())
	}
	base = sanitizeNamespaceComponent(base)
	base = strings.Trim(base, "-")
	if base == "" {
		base = "e2e"
	}
	suffix := fmt.Sprintf("%x", rand.Uint32()) // #nosec G404 // no need for cryptographic randomness
	if len(suffix) > suffixSize {
		suffix = suffix[:suffixSize]
	}
	return fmt.Sprintf("e2e-%s-%s", base, suffix)
}

func sanitizeNamespaceComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lastDash := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		isDigit := ch >= '0' && ch <= '9'
		isLetter := ch >= 'a' && ch <= 'z'
		if isDigit || isLetter {
			b.WriteByte(ch)
			lastDash = false
			continue
		}

		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}

	return b.String()
}
