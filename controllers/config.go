package controllers

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/scanners"
)

// ConfigMapReconcilerOptions defines the options for the ConfigMapReconciler.
type ConfigMapReconcilerOptions struct {
	// Scanner is the secret scanner to use.
	Scanner scanners.Scanner `json:"scanner"`
	// HashingAlgorithm is the hashing algorithm to use for secret values.
	HashingAlgorithm HashingAlgorithm `json:"hashingAlgorithm,omitempty"`
	// DefaultAction is the default action to take when a secret is detected.
	DefaultAction v1alpha1.Action `json:"defaultAction,omitempty"`
	// DefaultSeverity is the default severity level for detected secrets.
	DefaultSeverity v1alpha1.Severity `json:"defaultSeverity,omitempty"`
}

func (c *ConfigMapReconcilerOptions) WithDefaults() *ConfigMapReconcilerOptions {
	if c == nil {
		return (&ConfigMapReconcilerOptions{}).WithDefaults()
	}
	if c.HashingAlgorithm == "" {
		c.HashingAlgorithm = SHA256
	}
	if c.DefaultAction == "" {
		c.DefaultAction = v1alpha1.ReportOnly
	}
	if c.DefaultSeverity == "" {
		c.DefaultSeverity = v1alpha1.Medium
	}
	return c
}

func (c *ConfigMapReconcilerOptions) GetScanner() (scanners.Secret, error) {
	if c.Scanner == "" {
		return nil, errors.New("scanner is not set")
	}
	scanner, err := scanners.NewGitleaksScanner()
	if err != nil {
		return nil, err
	}
	return scanner, nil
}

type HashingAlgorithm string

const (
	SHA256 HashingAlgorithm = "sha256"
	SHA512 HashingAlgorithm = "sha512"
)

func (ha HashingAlgorithm) String() string {
	return string(ha)
}

func (ha HashingAlgorithm) Hash(value string) string {
	if ha == "" || value == "" {
		return ""
	}
	if ha.generateHash() == nil {
		panic(fmt.Sprintf("unsupported hashing algorithm %q", ha))
	}

	return ha.String() + ":" + hex.EncodeToString(ha.generateHash()(value))
}

func (ha HashingAlgorithm) generateHash() func(string) []byte {
	switch ha {
	case SHA256:
		return func(secret string) []byte {
			hash := sha256.Sum256([]byte(secret))
			return hash[:]
		}
	case SHA512:
		return func(secret string) []byte {
			hash := sha512.Sum512([]byte(secret))
			return hash[:]
		}
	default:
		return nil
	}
}
