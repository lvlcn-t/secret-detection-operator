# Secret Detection Operator<!-- omit from toc -->

<!-- markdownlint-disable-next-line -->
<p align="center">
    <a href="/../../commits/" title="Last Commit"><img alt="Last Commit" src="https://img.shields.io/github/last-commit/lvlcn-t/secret-detection-operator?style=flat"></a> 
    <a href="/../../issues" title="Open Issues"><img alt="Open Issues" src="https://img.shields.io/github/issues/lvlcn-t/secret-detection-operator?style=flat"></a>
</p>

- [About this component](#about-this-component)
- [Installation](#installation)
  - [Binary](#binary)
  - [Container Image](#container-image)
  - [Helm](#helm)
- [Usage](#usage)
  - [Image](#image)
- [Code of Conduct](#code-of-conduct)
- [Working Language](#working-language)
- [Support and Feedback](#support-and-feedback)
- [How to Contribute](#how-to-contribute)
- [Licensing](#licensing)

## About this component

The **Secret Detection Operator** is a Kubernetes operator designed to detect secret values stored insecurely in ConfigMaps and optionally remediate them by migrating these secrets into dedicated Secret objects. Detected secrets are reported via a custom Kubernetes resource (`ExposedSecret`), which can be configured for reporting only, automatic remediation, or explicit ignoring.

## Installation

You can deploy the Secret Detection Operator using one of the methods described below:

### Kustomize

To deploy the operator using Kustomize, you can use the following command:

```shell
kubectl apply -k "github.com/lvlcn-t/secret-detection-operator/config/default?ref=main"
```

### Helm

Deploy via Helm chart:

```shell
helm upgrade -i secret-detection-operator oci://ghcr.io/lvlcn-t/charts/secret-detection-operator \
  --version 0.1.0 \
  --namespace secret-detection-system \
  --create-namespace \
```

## Usage

The operator scans all ConfigMaps in your Kubernetes namespaces. If it detects secret-like values, it creates or updates an `ExposedSecret` custom resource.

By default, secrets are reported but not automatically remediated. You can adjust behavior via the `action` field in the `ExposedSecret` custom resource:

- `ReportOnly` (default): Report the secret without remediation.
- `AutoRemediate`: Automatically move the secret value into a dedicated Secret object.
- `Ignore`: Explicitly ignore and do not act upon this detection.

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

| Type       | Channel                                                                                                                   |
| ---------- | ------------------------------------------------------------------------------------------------------------------------- |
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