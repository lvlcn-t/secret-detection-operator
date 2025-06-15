# Custom Gitleaks Configuration

This document describes how to customize the Gitleaks scanner configuration using the `gitleaksConfig` field in `ScanPolicy`.

## Overview

The secret detection operator now supports custom Gitleaks configuration through the `ScanPolicy` CRD. This allows users to:

- Add custom secret detection rules
- Configure allowlist patterns to reduce false positives
- Adjust entropy thresholds for better detection accuracy
- Extend or replace default Gitleaks rules

## Configuration Structure

### GitleaksConfig

The `gitleaksConfig` field in `ScanPolicySpec` has the following structure:

```yaml
gitleaksConfig:
  useDefault: true  # Whether to extend default Gitleaks rules
  rules:            # Custom detection rules
    - id: "rule-id"
      description: "Human readable description"
      regex: "detection pattern"
      secretGroup: 1
      entropy: 3.5
      keywords: ["keyword1", "keyword2"]
  allowlist:        # Patterns to ignore
    - description: "What to ignore"
      regex: "ignore pattern"
      path: "file path pattern"
      stopWords: ["word1", "word2"]
```

### GitleaksRule Fields

- **id** (required): Unique identifier for the rule
- **description** (optional): Human-readable description of what the rule detects
- **regex** (required): Regular expression pattern for detection
- **secretGroup** (optional, default: 0): Which regex capture group contains the secret
- **entropy** (optional): Minimum Shannon entropy required (typically 3.0-4.5)
- **keywords** (optional): Additional keywords that must be present for detection

### GitleaksAllowlistRule Fields

- **description** (optional): Human-readable description of what to ignore
- **regex** (optional): Regular expression pattern to ignore
- **path** (optional): File path pattern to ignore
- **stopWords** (optional): Specific strings to ignore

## Examples

### Basic Custom Rule

```yaml
apiVersion: secretdetection.lvlcn-t.dev/v1alpha1
kind: ScanPolicy
metadata:
  name: api-key-detection
  namespace: myapp
spec:
  action: ReportOnly
  scanner: gitleaks
  gitleaksConfig:
    useDefault: true
    rules:
      - id: custom-api-key
        description: "Detect custom API key format"
        regex: "myapp-api-key-([a-zA-Z0-9]{32})"
        secretGroup: 1
        entropy: 3.5
```

### Multiple Rules with Allowlist

```yaml
apiVersion: secretdetection.lvlcn-t.dev/v1alpha1
kind: ScanPolicy
metadata:
  name: comprehensive-config
  namespace: production
spec:
  action: AutoRemediate
  minSeverity: Medium
  scanner: gitleaks
  enableConfigMapMutation: true
  gitleaksConfig:
    useDefault: true
    rules:
      - id: database-url
        description: "Database connection strings"
        regex: "(postgres|mysql|mongodb)://[^\\s\"]++"
        secretGroup: 0
        entropy: 3.0
      
      - id: jwt-token
        description: "JWT tokens"
        regex: "eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*"
        secretGroup: 0
        entropy: 4.0
    
    allowlist:
      - description: "Ignore test values"
        regex: "(test|example|sample|demo|localhost).*"
      
      - description: "Ignore documentation placeholders"
        stopWords:
          - "YOUR_SECRET_HERE"
          - "REPLACE_ME"
          - "TODO:"
```

### High-Security Configuration

```yaml
apiVersion: secretdetection.lvlcn-t.dev/v1alpha1
kind: ScanPolicy
metadata:
  name: high-security
  namespace: sensitive-app
spec:
  action: AutoRemediate
  minSeverity: Low
  scanner: gitleaks
  enableConfigMapMutation: true
  gitleaksConfig:
    useDefault: false  # Use only custom rules
    rules:
      - id: high-entropy-secrets
        description: "High entropy strings"
        regex: "[a-zA-Z0-9+/]{40,}"
        secretGroup: 0
        entropy: 4.5
        
      - id: specific-service-key
        description: "Service-specific key format"
        regex: "sk_[a-zA-Z0-9]{48}"
        secretGroup: 0
        entropy: 4.0
```

## Best Practices

1. **Start with Default Rules**: Set `useDefault: true` to extend the built-in Gitleaks rules
2. **Use Appropriate Entropy**: Higher entropy (4.0+) reduces false positives but may miss some secrets
3. **Test Regex Patterns**: Validate your regex patterns before deployment
4. **Implement Allowlists**: Use allowlists to handle known false positives
5. **Monitor Results**: Review detected secrets to fine-tune your configuration

## Migration from Default Configuration

If you're currently using the default Gitleaks configuration and want to add custom rules:

1. Set `useDefault: true` to maintain existing behavior
2. Add your custom rules to the `rules` array
3. Add any necessary allowlist patterns
4. Test in a non-production environment first

## Troubleshooting

### Invalid Regex Patterns

If you see warnings about invalid regex patterns in the logs:
- Check your regex syntax
- Escape special characters properly in YAML
- Test patterns using a regex validator

### No Secrets Detected

If your custom rules aren't detecting expected secrets:
- Verify the regex pattern matches your target format
- Check entropy thresholds aren't too high
- Ensure `useDefault` is set correctly
- Review allowlist patterns that might be excluding your secrets

### Performance Issues

If scanning becomes slow with custom rules:
- Optimize regex patterns for efficiency
- Avoid overly broad patterns
- Consider using keywords to narrow detection scope
