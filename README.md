# 🔐 Secret Detection Operator<!-- omit from toc -->

<p align="center">
    <a href="/../../commits/" title="Last Commit"><img alt="Last Commit" src="https://img.shields.io/github/last-commit/lvlcn-t/secret-detection-operator?style=flat"></a>
    <a href="/../../issues" title="Open Issues"><img alt="Open Issues" src="https://img.shields.io/github/issues/lvlcn-t/secret-detection-operator?style=flat"></a>
</p>

- [📖 Overview](#-overview)
- [🚀 Quick Installation](#-quick-installation)
  - [Kustomize](#kustomize)
  - [Helm](#helm)
- [🛠️ How it Works](#️-how-it-works)
- [🛡️ Configuration with ScanPolicy](#️-configuration-with-scanpolicy)
  - [Example ScanPolicy](#example-scanpolicy)
- [📌 Example Usage](#-example-usage)
- [📊 Metrics](#-metrics)
- [Code of Conduct](#code-of-conduct)
- [Working Language](#working-language)
- [Support and Feedback](#support-and-feedback)
- [How to Contribute](#how-to-contribute)
- [Licensing](#licensing)

---

## 📖 Overview

The **Secret Detection Operator** scans your Kubernetes ConfigMaps for sensitive data such as passwords or tokens. It can automatically remediate detected secrets by migrating them into secure Kubernetes Secret resources, or simply report them for manual action.

It leverages customizable policies (`ScanPolicy`) to tailor secret handling across namespaces, ensuring sensitive data remains secure and compliant with your organization's standards.

---

## 🚀 Quick Installation

You can deploy the operator quickly using either Kustomize or Helm.

### Kustomize

Apply the latest configuration directly:

```shell
kubectl apply -k "github.com/lvlcn-t/secret-detection-operator/config/default?ref=main"
```

### Helm

Install via Helm chart:

```shell
VERSION="0.1.0"

helm upgrade -i secret-detection-operator \
  oci://ghcr.io/lvlcn-t/charts/secret-detection-operator \
  --version $VERSION \
  --namespace secret-detection-system \
  --create-namespace
```

---

## 🛠️ How it Works

The operator:

1. Scans ConfigMaps across your cluster for secret-like data.
2. Reports findings via the `ExposedSecret` custom resource.
3. Remediates detected secrets automatically based on your configuration, moving sensitive values to secure Kubernetes Secrets.

You can define specific behaviors for reporting and remediation through customizable policies (`ScanPolicy`).

---

## 🛡️ Configuration with ScanPolicy

`ScanPolicy` resources configure detection and remediation behaviors per namespace:

- **Default Action:**
  - `ReportOnly`: Logs detections without modifying ConfigMaps (default).
  - `AutoRemediate`: Moves secrets to Kubernetes Secrets and optionally removes them from ConfigMaps.
  - `Ignore`: Completely ignores detections.

- **Severity Threshold:** Only secrets at or above this severity (`Low`, `Medium`, `High`, `Critical`) will trigger actions.

- **Excluded Keys:** Ignore specific keys to avoid false positives.

- **ConfigMap Mutation:** Optionally remove secret keys after migrating them.

- **Scanner Engine:** Currently only `gitleaks` is supported, but more engines may be added in the future.

- **Hash Algorithm:** Select how detected secrets are reported (`sha256`, `sha512`, or `none`).

### Example ScanPolicy

```yaml
apiVersion: secret-detection-operator.lvlcn-t.io/v1alpha1
kind: ScanPolicy
metadata:
  name: default-policy
  namespace: default
spec:
  action: AutoRemediate
  minSeverity: Medium
  excludedKeys:
    - non-secret-token
    - dummy-password
  enableConfigMapMutation: true
  scanner: gitleaks
  hashAlgorithm: sha256
```

If no ScanPolicy is defined, defaults (`ReportOnly`, `Medium` severity, `gitleaks` scanner) apply.

---

## 📌 Example Usage

When a secret-like value is detected in a ConfigMap, an `ExposedSecret` resource is created:

```yaml
apiVersion: secret-detection-operator.lvlcn-t.io/v1alpha1
kind: ExposedSecret
metadata:
  name: example-config-map-example-key
  namespace: default
spec:
  action: ReportOnly
  severity: Critical
  notes: Automatically reported by secret-detection-operator
status:
  ConfigMapRef:
    Name: example-config-map
  Key: example-key
  Scanner: gitleaks
  DetectedValue: sha256:<hash>
  Phase: Detected
  Message: Secret detected in ConfigMap 'example-config-map' for key 'example-key'
  LastUpdateTime: "2024-01-01T00:00:00Z"
  ObservedGeneration: 1
```

Upon remediation, the secret value is safely stored in a Kubernetes Secret and the ExposedSecret updated accordingly:

```yaml
apiVersion: secret-detection-operator.lvlcn-t.io/v1alpha1
kind: ExposedSecret
metadata:
  name: example-config-map-example-key
  namespace: default
spec:
  action: AutoRemediate
  severity: Critical
  notes: Automatically reported by secret-detection-operator
status:
  ConfigMapRef:
    Name: example-config-map
  Key: example-key
  Scanner: gitleaks
  DetectedValue: sha256:<hash>
  SecretRef:
    Name: example-config-map-example-key
  Phase: Remediated
  Message: Secret auto-remediated from ConfigMap 'example-config-map' for key 'example-key'
  LastUpdateTime: "2024-01-01T00:00:00Z"
  ObservedGeneration: 2
```

## 📊 Metrics

The Secret Detection Operator exports the following custom Prometheus metrics to help you monitor its performance and behavior:

| Metric Name                  | Type      | Labels                  | Description                                                                                                                      |
| ---------------------------- | --------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `configmap_reconciles_total` | Counter   | `namespace`             | Total number of ConfigMap reconcile loops executed.                                                                              |
| `reconcile_duration_seconds` | Histogram | `namespace`             | Duration (seconds) of each reconcile loop.                                                                                       |
| `keys_scanned`               | Histogram | `namespace`             | Number of data keys examined in each ConfigMap.                                                                                  |
| `secrets_detected_total`     | Counter   | `namespace`, `severity` | Total secrets detected, broken down by severity (`Unknown`, `Low`, `Medium`, `High`, `Critical`).                                |
| `secrets_remediated_total`   | Counter   | `namespace`             | Total secrets automatically remediated (migrated into Secrets).                                                                  |
| `configmaps_mutated_total`   | Counter   | `namespace`             | Total ConfigMaps that were mutated to remove secret keys.                                                                        |
| `reconcile_errors_total`     | Counter   | `namespace`, `stage`    | Total errors during reconciliation, labeled by stage:<br>`load_policy`, `get_configmap`, `process_key`, `remediate_secret`, etc. |

## Code of Conduct

This project has adopted the [Contributor Covenant](https://www.contributor-covenant.org/) in version 2.1 as our code of
conduct. Please see the details in our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). All contributors must abide by the code
of conduct.

## Working Language

We decided to apply _English_ as the primary project language.

Consequently, all content will be made available primarily in English.
We also ask all interested people to use English as the preferred language to create issues,
in their code (comments, documentation, etc.) and when you send requests to us.
The application itself and all end-user facing content will be made available in other languages as needed.

## Support and Feedback

The following channels are available for discussions, feedback, and support requests:

| Type       | Channel                                                                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **Issues** | [![General Discussion](https://img.shields.io/github/issues/lvlcn-t/secret-detection-operator?style=flat-square)](/../../issues/new/choose) |

## How to Contribute

Contribution and feedback is encouraged and always welcome. For more information about how to contribute, the project
structure, as well as additional contribution information, see our [Contribution Guidelines](./CONTRIBUTING.md). By
participating in this project, you agree to abide by its [Code of Conduct](./CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright (c) 2024 lvlcn-t.

Licensed under the **MIT** (the "License"); you may not use this file except in compliance with
the License.

You may obtain a copy of the License at <https://www.mit.edu/~amini/LICENSE.md>.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the [LICENSE](./LICENSE) for
the specific language governing permissions and limitations under the License.