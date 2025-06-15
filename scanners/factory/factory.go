package factory

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lvlcn-t/secret-detection-operator/scanners"
	"github.com/lvlcn-t/secret-detection-operator/scanners/gitleaks"
	"github.com/stretchr/testify/require"
)

var defaultScanners = newDefaultScanners()

func newDefaultScanners() map[scanners.Name]scanners.Scanner {
	gs := NewScannerOrDie(nil, gitleaks.New)
	return map[scanners.Name]scanners.Scanner{
		gs.Name().Normalize(): gs,
	}
}

// Get returns the scanner for the given name with default configuration.
// If the scanner is not found, it returns nil.
func Get(ctx context.Context, name scanners.Name, cfg scanners.Config) (scanners.Scanner, error) {
	if cfg != nil {
		return cfg.Scanner(ctx)
	}

	if scanner, ok := defaultScanners[name.Normalize()]; ok {
		return scanner, nil
	}

	return nil, errors.New("scanner not found")
}

// Set sets the scanner for the given name.
// It is used for testing purposes to inject a different scanner implementation.
func Set(t testing.TB, name scanners.Name, scanner scanners.Scanner) {
	t.Helper()
	defaultScanners[name] = scanner
}

// NewScannerOrDie creates a new scanner using the provided function.
// It panics if the scanner cannot be created.
// If used in a test, it will use the test's context and fail the test on error.
// If not used in a test, just pass a nil testing.TB.
func NewScannerOrDie(t testing.TB, f func(ctx context.Context, cfg scanners.Config) (scanners.Scanner, error)) scanners.Scanner {
	ctx := context.Background()
	fail := func(err error) { panic(err) }
	if t != nil {
		t.Helper()
		ctx = t.Context()
		fail = func(err error) { require.NoError(t, err) }
	}

	scanner, err := f(ctx, nil)
	if err != nil {
		fail(fmt.Errorf("failed to create scanner: %w", err))
	}
	return scanner
}
