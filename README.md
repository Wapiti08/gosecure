# gosecure

`gosecure` is an experimental security analysis tool for explaining security-sensitive behavior changes between Go package releases.

Instead of building another general-purpose dependency vulnerability scanner, gosecure focuses on a different question:

> What new security-relevant behavior does this package version introduce?

The goal is to help maintainers review dependency upgrades and detect suspicious changes before they are classified as a known vulnerability or malicious package.

## Project status

gosecure is in an early design and development stage. The repository currently contains foundations for Go module discovery, vulnerability lookup, dependency graphs, version diffs, and risk signals. The behavior-analysis workflow described below is the intended direction and is not yet fully implemented.

## Expected features

### Release behavior diff

Compare two versions of a Go module and report newly introduced security-sensitive behavior, including:

- process and shell execution;
- outbound network access and newly referenced domains;
- reads of credentials, environment variables, home directories, or other sensitive files;
- use of CGO, `unsafe`, reflection, or embedded executables;
- changes to `go:generate`, build scripts, and platform-specific files;
- added binary assets, generated code, or heavily obfuscated source.

### Reachability and evidence

- Build call graphs to distinguish reachable behavior from unused code.
- Show the source location and call path for each finding.
- Explain what changed between releases instead of returning only an opaque risk score.
- Account for build tags, target operating systems, and architectures where possible.

### Source and release provenance

- Compare Git tags, module proxy source archives, and repository contents.
- Highlight source files or artifacts that exist in a release but not in the expected revision.
- Detect repository, module path, or maintainer ownership changes.
- Surface unusual release timing or version-history anomalies as supporting evidence.

### Policy and automation

- Produce `allow`, `warn`, or `block` decisions from configurable policies.
- Support human-readable, JSON, and SARIF reports.
- Run locally or in CI without requiring a specific source-hosting platform.
- Allow known or reviewed behavior to be suppressed with an auditable justification.

## Example report

The intended output will look similar to:

```text
example.com/module v1.4.2 -> v1.4.3

HIGH    introduced process execution via os/exec.Command
        internal/update/install.go:48
        reachable from update.Apply

MEDIUM  introduced outbound connection to telemetry.example.com
        internal/client/report.go:27

INFO    repository ownership changed before this release

Decision: manual review required
```

## Scope

The initial scope is deliberately Go-specific. Multi-ecosystem dependency discovery and known-CVE matching are not primary product goals: GitHub Dependency Review, Dependabot, OSV-Scanner, Trivy, Grype, and other mature tools already cover those use cases well.

Known vulnerability data may still be included as supporting context, but gosecure's main value should come from behavioral and provenance evidence that is not dependent on an existing advisory.

## Current repository structure

- `cmd/gosecure/`: CLI entrypoint and future command wiring.
- `internal/config/`: shared runtime configuration.
- `pkg/scanner/`: current Go module dependency discovery.
- `pkg/vuln/`: current vulnerability backends and caching.
- `pkg/graph/`: dependency graph representation and algorithms.
- `pkg/diff/`: dependency snapshot and version comparison foundations.
- `pkg/risk/`: current risk signals and policy foundations.

As the new direction is implemented, the planned core components are:

- `pkg/source/`: acquire and normalize two package releases.
- `pkg/behavior/`: identify security-sensitive capabilities and API usage.
- `pkg/callgraph/`: calculate reachability and evidence paths.
- `pkg/diff/`: compare behavior, source, and artifacts between releases.
- `pkg/provenance/`: verify source and release consistency.
- `pkg/policy/`: turn findings into configurable decisions.
- `pkg/report/`: render terminal, JSON, and SARIF output.

## Non-goals

- Replacing Dependabot or GitHub Dependency Review.
- Becoming a universal lockfile or container vulnerability scanner.
- Competing on the number of supported package ecosystems.
- Treating a single unexplained numeric risk score as a security verdict.

## Development

```bash
go mod download
go test ./...
```

The CLI is not yet ready for general use.
