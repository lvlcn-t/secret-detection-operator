# AGENTS.md

Guidelines for agentic coding assistants working in this repository.

## What this repo is

A Kubernetes operator that scans ConfigMaps for exposed secrets and
optionally remediates them by migrating values to proper Secrets.
Written in Go using controller-runtime. The main reconciliation loop
lives in `controllers/`, CRD types in `apis/v1alpha1/`, and scanner
implementations in `scanners/`.

## Build and tooling

```bash
# Generate deepcopy, mocks (moq), and RBAC/CRD manifests
go generate ./...
make gen         # deepcopy only (controller-gen)
make manifests   # RBAC + CRD + Helm chart sync

# Install codegen tools into ./bin/
make bin/controller-gen
```

Pre-commit hooks enforce `go generate`, `go mod tidy`, `gofumpt`,
`golangci-lint --fix`, and `gitleaks` on every commit.
Run them manually with `pre-commit run --all-files`.

## Test commands

All unit tests are marked short and must be run with `-test.short`.
E2E tests skip when that flag is set.

```bash
# Run all unit tests
go test -race -count=1 -test.short ./...

# Run a single test function
go test -race -count=1 -test.short -run TestReconcile ./controllers/...

# Run a specific sub-test
go test -race -count=1 -test.short -run "TestReconcile/detects_secret_-_report_only" ./controllers/...

# Run tests in a specific package
go test -race -count=1 -test.short ./scanners/...
```

## Lint and format

```bash
# Lint (same config CI uses)
golangci-lint run --config .golangci.yaml ./...

# Auto-fix formatting and lint issues
golangci-lint run --config .golangci.yaml --fix ./...

# Format only (gofumpt is the formatter, stricter than gofmt)
gofumpt -l -w .
```

Key linter rules (see `.golangci.yaml`):

- `funlen`: max **50 statements** per function (lines limit disabled).
- `gocyclo`: max complexity **15**.
- `mnd`: magic numbers banned in args, case, condition, and return
  positions; `0`, `1`, `2`, `3` are exempt.
- `gochecknoinits`: `init()` is banned except where explicitly
  `//nolint:gochecknoinits` with a comment explaining why.
- `nolintlint`: every `//nolint` directive must name a specific linter.
- `dupl`: flags blocks of ≥ 100 identical tokens.
- `interface{}` → `any` (enforced by gofmt rewrite rule).

## Code style

### Imports

Group imports in three blocks, separated by blank lines:

```go
import (
    // 1. stdlib
    "context"
    "fmt"

    // 2. third-party
    "github.com/go-logr/logr"
    corev1 "k8s.io/api/core/v1"

    // 3. internal (module path: github.com/lvlcn-t/secret-detection-operator/...)
    "github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
)
```

`goimports` enforces this automatically. The local prefix is
`github.com/lvlcn-t/secret-detection-operator`.

Alias stdlib errors when importing alongside API errors to avoid
collision:

```go
import (
    stderrors "errors"
    "k8s.io/apimachinery/pkg/api/errors"
)
```

### Formatting

- `gofumpt` (superset of `gofmt`) is the canonical formatter.
- Line length is **140 characters** (linter enforcement).
- Use `any` instead of `interface{}` everywhere.

### Naming

- **Types and constructors**: PascalCase (`ConfigMapReconciler`,
  `NewConfigMapReconciler`).
- **String-typed enumerations** are defined as typed `string` aliases
  with named constants (`Action`, `Phase`, `Severity`, `HashAlgorithm`).
  Always implement a `String() string` method.
- **Test helpers** use `t.Helper()` as their first line.
- **Internal reconciliation state** is grouped into a single `recCtx`
  struct rather than passing many parameters.
- **kubebuilder markers** (`+kubebuilder:...`) live directly above the
  type or method they annotate, separated from other comments by a blank
  line only when the block is long.

### Error handling

- Wrap errors with context using `fmt.Errorf("...: %w", err)`.
- Use `client.IgnoreNotFound(err)` for Kubernetes not-found errors in
  reconcilers instead of a manual `errors.IsNotFound` guard.
- In `Reconcile`, always return `ctrl.Result{}` alongside a non-nil
  error; never return a non-zero requeue interval with an error.
- Use `//nolint:gochecknoinits` (with reason comment) for the `init()`
  in `main.go` that registers schemes — this is the accepted
  controller-runtime pattern.
- Do not `panic` in production code paths; `panic` is only acceptable
  in unrecognized-enum `default` branches (`resolver.go`) as a sentinel
  for programmer errors.

### Interfaces and mocks

- Interfaces are declared in the package that **uses** them, not where
  the implementation lives (`scanners.Scanner`, `scanners.Config`).
- Mocks are generated with `moq` via `//go:generate go tool moq ...`.
  Generated files are named `<source>_moq.go` and committed.
- Compile-time interface assertions use blank-identifier assignment:
  `var _ reconcile.Reconciler = (*ConfigMapReconciler)(nil)`.

### Testing patterns

- Tests use a fluent builder framework (`test.Framework` /
  `test.Unittest`) defined in `test/`. Use it for all controller tests.
- Unit tests call `markShort(t)` (via `fw.Unit(t)`) and require the
  `-test.short` flag; add this flag to every `go test` invocation.
- Use `github.com/stretchr/testify/require` for assertions; prefer
  `require` over `assert` so failures stop immediately.
- Use `sigs.k8s.io/controller-runtime/pkg/client/fake` for the
  Kubernetes client; use `interceptor.Funcs` to inject faults.
- Assert only the non-zero fields that matter to the scenario using
  `test.AssertMatchesNonZeroFields` to keep tests stable against
  timestamp and metadata churn.
- Test functions follow `Test<Subject>_<Scenario>` naming.
- Test packages use the `_test` suffix (external package tests):
  `package controllers_test`.

### Kubernetes / controller-runtime conventions

- RBAC markers go directly above `Reconcile` on the reconciler struct.
- `SetupWithManager` is always a separate method, never inlined.
- Use `logr.FromContextAsSlogLogger(ctx)` to extract the logger;
  always pass `ctx` as the first argument to slog log calls
  (`log.InfoContext(ctx, ...)`).
- Prefer `client.ObjectKeyFromObject(obj)` over constructing
  `types.NamespacedName` by hand.
- Status updates use `r.Status().Update(ctx, obj)` on a `DeepCopy()`
  of the resource.

### Code generation

After adding or changing a CRD type or interface, run:

```bash
go generate ./...   # regenerates deepcopy + mocks
make manifests      # regenerates CRD YAML and Helm chart
```

Commit the generated files alongside the change that triggered them.

## Repository layout

```text
apis/v1alpha1/     → CRD types, enums, builder, deepcopy (generated)
controllers/       → Reconciler, reconciliation context, metrics, resolver
scanners/          → Scanner interface, Severity/Name types, moq mock
scanners/factory/  → Scanner registry; Set() for test injection
scanners/gitleaks/ → Gitleaks scanner implementation
config/            → Operator config loading and validation
test/              → Test framework (Framework, Unittest, helpers)
hack/              → Shell scripts for chart/kustomize sync
chart/             → Helm chart
config/            → Kustomize manifests and CRD bases
```
