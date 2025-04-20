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

type T interface {
	require.TestingT
	Helper()
	Context() context.Context
}

type Framework[Type T] struct {
	t Type
}

func NewFramework[Type T](t Type) *Framework[Type] {
	return &Framework[Type]{
		t: t,
	}
}

func (f *Framework[Type]) Unit(t Type) *Unittest[Type] {
	f.t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	return &Unittest[Type]{
		T:          t,
		client:     fake.NewClientBuilder().WithScheme(scheme),
		scheme:     scheme,
		assertions: []func(*Unittest[Type], ctrl.Result, error){},
	}
}
