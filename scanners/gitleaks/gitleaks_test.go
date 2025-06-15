package gitleaks

// import (
// 	"testing"

// 	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// )

// func TestNewGitleaksScannerWithConfig(t *testing.T) {
// 	tests := []struct {
// 		name           string
// 		config         *Config
// 		testValue      string
// 		expectedSecret bool
// 		description    string
// 	}{
// 		{
// 			name: "default config with useDefault=true",
// 			config: &Config{
// 				UseDefault: true,
// 			},
// 			testValue:      "ghp_1234567890abcdef1234567890abcdef12345678",
// 			expectedSecret: true,
// 			description:    "Should detect GitHub token with default rules",
// 		},
// 		{
// 			name: "custom rule for API key pattern",
// 			config: &Config{
// 				UseDefault: false,
// 				Rules: []Rule{
// 					{
// 						ID:          "custom-api-key",
// 						Description: "Custom API key pattern",
// 						Regex:       `api[_-]?key[_-]?[:=]\s*["\']?([a-zA-Z0-9]{32})["\']?`,
// 						SecretGroup: 1,
// 						Entropy:     3.0,
// 					},
// 				},
// 			},
// 			testValue:      `api_key: "abcd1234567890efgh1234567890ijkl"`,
// 			expectedSecret: true,
// 			description:    "Should detect custom API key pattern",
// 		},
// 		{
// 			name: "allowlist rule to ignore false positive",
// 			config: &Config{
// 				UseDefault: true,
// 				Allowlist: []AllowlistRule{
// 					{
// 						Description: "Ignore test values",
// 						Regex:       `test.*value`,
// 					},
// 				},
// 			},
// 			testValue:      "test_secret_value_ghp_1234567890abcdef1234567890abcdef12345678",
// 			expectedSecret: false,
// 			description:    "Should ignore patterns matching allowlist",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			scanner, err := newGitleaksScanner(t.Context(), tt.config)
// 			require.NoError(t, err)
// 			require.NotNil(t, scanner)

// 			result := scanner.IsSecret(tt.testValue)
// 			assert.Equal(t, tt.expectedSecret, result, tt.description)
// 		})
// 	}
// }

// func TestNewGitleaksScanner_WithConfig_InvalidRegex(t *testing.T) {
// 	// Test that invalid regex patterns don't crash the scanner
// 	config := &Config{
// 		UseDefault: false,
// 		Rules: []Rule{
// 			{
// 				ID:    "invalid-regex",
// 				Regex: `[unclosed bracket`,
// 			},
// 		},
// 	}

// 	// Expect a warning log but no panic
// 	scanner, err := newGitleaksScanner(t.Context(), config)
// 	require.NoError(t, err)
// 	require.NotNil(t, scanner)

// 	// Scanner should still work, just without the invalid rule
// 	result := scanner.IsSecret("some test value")
// 	assert.False(t, result)
// }

// func TestGet_WithConfig(t *testing.T) {
// 	config := &Config{
// 		UseDefault: true,
// 	}

// 	scanner, err := Get(t.Context(), v1alpha1.ScannerGitleaks, config)
// 	require.NoError(t, err)
// 	require.NotNil(t, scanner)
// 	assert.Equal(t, v1alpha1.ScannerGitleaks, scanner.Name())
// }

// func TestGet_WithConfig_UnsupportedScanner(t *testing.T) {
// 	config := &Config{
// 		UseDefault: true,
// 	}

// 	scanner, err := Get(t.Context(), "UnsupportedScanner", config)
// 	require.Error(t, err)
// 	assert.Nil(t, scanner)
// }

// func TestGet_WithConfig_NilConfig(t *testing.T) {
// 	// Should fall back to default scanner when config is nil
// 	scanner, err := Get(t.Context(), v1alpha1.ScannerGitleaks, nil)
// 	require.NoError(t, err)
// 	require.NotNil(t, scanner)
// 	assert.Equal(t, v1alpha1.ScannerGitleaks, scanner.Name())
// }
