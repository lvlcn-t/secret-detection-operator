package test

import (
	"testing"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type Framework struct {
	t testing.TB
}

func NewFramework[T testing.TB](t T) *Framework {
	return &Framework{
		t: t,
	}
}

func (f *Framework) Unit(t testing.TB) *Unittest {
	f.t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	return &Unittest{
		T:          t,
		builder:    fake.NewClientBuilder().WithScheme(scheme),
		scheme:     scheme,
		assertions: []func(*Unittest, ctrl.Result, error){},
	}
}
