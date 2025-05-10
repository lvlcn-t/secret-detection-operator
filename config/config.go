package config

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/lvlcn-t/go-kit/config"
	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/spf13/afero"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// AppName is the name of the application.
	// It is used to derive the configuration file name
	// and the environment variable prefix.
	AppName = "secret-detection-operator"

	// AppURL is the URL of the application.
	// It is used to derive the leader election ID.
	AppURL = "operator." + v1alpha1.APIGroup
)

// Config represents the configuration for the secret detection operator.
type Config struct {
	// ScanPolicy is the default scan policy to use for scanning secrets.
	// It is used when no scan policy is present in the namespace of the ConfigMap that is being reconciled.
	ScanPolicy *v1alpha1.ScanPolicy
}

// Validate validates the [Config] against the Kubernetes API server.
func (cfg *Config) Validate(ctx context.Context, c client.Client) error {
	var errs []error
	err := validateObject(ctx, c, cfg.ScanPolicy)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to validate (%T).ScanPolicy: %w", cfg, err))
	}

	return errors.Join(errs...)
}

// Load loads the [Config] from the provided path.
// If the path is empty, it will use the default fallback path (~/.config/[AppName]/config.yaml).
// It will also load the configuration from the environment variables with the prefix [AppName].
func Load(path string) (*Config, error) {
	config.SetName(AppName)
	cfg, err := config.Load[rawConfig](path)
	if err != nil && !errors.Is(err, &config.ErrConfigEmpty{}) {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return cfg.toConfig()
}

// LoadFS loads the [Config] from the provided path using the provided file system.
// This is useful for testing purposes.
func LoadFS(path string, fsys fs.FS) (*Config, error) {
	config.SetFs(afero.FromIOFS{FS: fsys})
	return Load(path)
}

// rawConfig is the raw configuration struct which is compliant with a Kubernetes ConfigMap.
// It is used to unmarshal the configuration from the file or environment variables.
type rawConfig struct {
	ScanPolicy string `json:"defaultScanPolicy" yaml:"defaultScanPolicy" mapstructure:"defaultScanPolicy"`
}

func (rc rawConfig) IsEmpty() bool {
	return cmp.Equal(rc, rawConfig{})
}

func (rc *rawConfig) toConfig() (c *Config, err error) {
	var cfg Config
	cfg.ScanPolicy, err = loadStringValue(rc.ScanPolicy, defaultScanPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to decode scan policy: %w", err)
	}

	return &cfg, nil
}

// validationMeta is the metadata used for all default objects.
// It's needed for the validation of the objects against the Kubernetes API server.
var validationMeta = metav1.ObjectMeta{
	GenerateName: "validation-",
	Namespace:    "secret-detection-system",
}

var defaultScanPolicy = &v1alpha1.ScanPolicy{
	ObjectMeta: validationMeta,
	Spec: v1alpha1.ScanPolicySpec{
		Action:        v1alpha1.ActionReportOnly,
		MinSeverity:   v1alpha1.SeverityMedium,
		Scanner:       v1alpha1.ScannerGitleaks,
		HashAlgorithm: v1alpha1.AlgorithmNone,
	},
}

// bufferSize determines how far into the stream the decoder
// will look to figure out whether the input is YAML or JSON.
const bufferSize = 1024

// loadStringValue loads a value from a string.
// If the string is empty, it returns the default value.
// Returns an error if the string cannot be decoded into the value type.
func loadStringValue[T runtime.Object](raw string, defaultVal T) (T, error) {
	// obj ensures that we always have a non-nil object to work with.
	obj := defaultVal.DeepCopyObject().(T)
	if raw == "" {
		return obj, nil
	}

	d := yaml.NewYAMLOrJSONDecoder(strings.NewReader(raw), bufferSize)
	if err := d.Decode(&obj); err != nil {
		return obj, fmt.Errorf("failed to decode value: %w", err)
	}

	return obj, nil
}

// validateObject validates the given object against the Kubernetes API server.
// It uses a dry run to check if the object is valid.
func validateObject(ctx context.Context, c client.Client, obj client.Object) error {
	err := c.Create(ctx, obj, client.DryRunAll)
	if err == nil {
		return nil
	}

	if apierrors.IsInvalid(err) {
		// * Note: if the caller wants to inspect the error, we shouldn't wrap it.
		return fmt.Errorf("invalid object: %w", err)
	}

	return fmt.Errorf("something went wrong while validating the object against the API server: %w", err)
}
