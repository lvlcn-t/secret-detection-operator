package config

import (
	"fmt"

	"github.com/lvlcn-t/go-kit/config"
)

type Config struct {
	MetricsAddr string `json:"metricsAddr,omitempty"`
	HealthAddr  string `json:"healthAddr,omitempty"`
	LeaderElect bool   `json:"leaderElect,omitempty"`
}

// IsEmpty always returns false, since an empty config should be evaluated as a valid config.
func (c *Config) IsEmpty() bool {
	return false
}

func (c *Config) WithDefaults() *Config {
	if c == nil {
		cfg := &Config{}
		return cfg.WithDefaults()
	}
	if c.MetricsAddr == "" {
		c.MetricsAddr = ":9090"
	}
	if c.HealthAddr == "" {
		c.HealthAddr = ":8080"
	}
	return c
}

// Load loads the configuration from the specified path.
func Load(path string) (*Config, error) {
	config.SetName("secret-detection-operator")
	cfg, err := config.Load[*Config](path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	cfg = cfg.WithDefaults()
	if err = config.Validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}
