package test

import (
	"context"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type TestingT interface {
	require.TestingT
	Helper()
	Context() context.Context
}

type Framework[T TestingT] struct {
	t T
}

func NewFramework[T TestingT](t T) *Framework[T] {
	return &Framework[T]{
		t: t,
	}
}

func (f *Framework[T]) Unit(t T) *Unittest[T] {
	f.t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	return &Unittest[T]{
		T:          t,
		client:     fake.NewClientBuilder().WithScheme(scheme),
		scheme:     scheme,
		assertions: []func(*Unittest[T], ctrl.Result, error){},
	}
}
