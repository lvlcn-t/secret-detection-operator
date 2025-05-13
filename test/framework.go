package test

import (
	"testing"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/config"
	"github.com/lvlcn-t/secret-detection-operator/test/data"
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
	markShort(t)
	scheme := newScheme(t)
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

// newScheme creates a new [runtime.Scheme] for the test.
// It includes the corev1 and v1alpha1 schemes.
func newScheme(t testing.TB) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	return scheme
}

// loadConfig loads the configuration from the embedded filesystem.
// It will fail the test if the configuration cannot be loaded.
func loadConfig(t testing.TB) *config.Config {
	t.Helper()
	cfg, err := config.LoadFS("config.yaml", data.FS)
	require.NoError(t, err)
	return cfg
}

// markShort marks the test as short-running. It will skip the test if the -test.short flag is not set.
func markShort(t testing.TB) {
	t.Helper()
	if !testing.Short() {
		t.Skip("To run this test, please use the -test.short flag")
	}
}

// TODO: remove this once we use the framework for e2e tests.
var _ = markLong

// markLong marks the test as long-running. It will skip the test if the -test.short flag is set.
func markLong(t testing.TB) {
	t.Helper()
	if testing.Short() {
		t.Skip("To run this test, remove the -test.short flag")
	}
}
