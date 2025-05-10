package test

import (
	"testing"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/config"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type Framework struct {
	T testing.TB
}

func NewFramework(t testing.TB) *Framework {
	return &Framework{T: t}
}

func (f *Framework) Unit(t testing.TB) *Unittest {
	f.T.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cfg := loadConfig(t)
	// Always make sure our default config is valid.
	require.NoError(t, cfg.Validate(t.Context(), fake.NewClientBuilder().WithScheme(scheme).Build()))
	return &Unittest{
		T:          t,
		builder:    fake.NewClientBuilder().WithScheme(scheme),
		cfg:        cfg,
		scheme:     scheme,
		assertions: []func(*Unittest, ctrl.Result, error){},
	}
}

func loadConfig(t testing.TB) *config.Config {
	t.Helper()
	cfg, err := config.LoadFS("config.yaml", FS)
	require.NoError(t, err)
	return cfg
}
