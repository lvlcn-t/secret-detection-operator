package config

import (
	"reflect"

	"github.com/lvlcn-t/go-kit/config"
	"github.com/lvlcn-t/secret-detection-operator/controllers"
)

type Config struct {
	MetricsAddr string `json:"metricsAddr,omitempty"`
	HealthAddr  string `json:"healthAddr,omitempty"`
	LeaderElect bool   `json:"leaderElect,omitempty"`

	ConfigMapReconciler *controllers.ConfigMapReconcilerOptions `json:"configMap,omitempty"`
}

func (c *Config) IsEmpty() bool {
	return reflect.DeepEqual(c, &Config{})
}

func (c *Config) WithDefaults() *Config {
	if c == nil {
		return (&Config{}).WithDefaults()
	}
	if c.MetricsAddr == "" {
		c.MetricsAddr = ":9090"
	}
	if c.HealthAddr == "" {
		c.HealthAddr = ":8080"
	}
	if c.ConfigMapReconciler == nil {
		c.ConfigMapReconciler = (&controllers.ConfigMapReconcilerOptions{}).WithDefaults()
	}
	return c
}

// Load loads the configuration from the specified path.
func Load(path string) (*Config, error) {
	config.SetName("secret-detection-operator")
	cfg, err := config.Load[*Config](path)
	if err != nil {
		return nil, err
	}
	return cfg.WithDefaults(), nil
}
