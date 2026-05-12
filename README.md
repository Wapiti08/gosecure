# gosecure
A golang-based high-performance dependency scanning tool


## Core Features
- extreme-speed scanning (compared with govulncheck)
- golang-based, extensible
- deep transitive dependency scanning (depth configurable), catching vulnerabilities hidden in nested deps
- plugin-support, multi-language support
- dependency diff & risk scoring: compare two lockfiles or releases, flag newly introduced packages, score by age, popularity, maintainer signals, and install scripts (mitigates axios-style supply-chain risk).

## Structure

- `cmd/gosecure/`: CLI entrypoint (flags, subcommands, wiring into scanners and diff/risk flows).

- `internal/config/`: shared CLI/runtime configuration (loaded by `cmd`).

- `pkg/scanner/`: dependency discovery and per-ecosystem scanners.

    - `scanner.go`: `Scanner` / `VulnChecker` interfaces, `Vulnerability`, helpers such as `ScanProject`.

    - `gomod_scanner.go`: Go modules (`go.mod` layers: modfile / artifacts / `go list`, configurable transitive depth where applicable).

    - `concurrent.go`: reserved for shared concurrency helpers used by scanners (optional).

    - `scanner_test.go`: unit tests for the scanner package.

- `pkg/vuln/`: vulnerability backends and wrappers (`VulnChecker` implementations: OSV, NVD, caching, rate limiting, etc.).

- `pkg/graph/`: dependency graph representation and algorithms (depth limits, visualization, shared by scanners and reports).

- `pkg/diff/`: compare two dependency snapshots (e.g. two lockfiles or two resolved graphs); output added/removed/changed packages.

- `pkg/risk/`: pure scoring and policy (package age, popularity proxies, maintainer signals, post-install script flags); consumed by CLI or diff reports.

## Related tools (for comparison)

These are mature open-source projects in the same problem space (dependency + vulnerability intelligence). Use them as benchmarks for features, accuracy, and UX—not as endorsements.

- **[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)** — official Go vulnerability scanner (call-graph aware for Go code paths).
- **[OSV-Scanner](https://github.com/google/osv-scanner)** — multi-ecosystem scanner built around the [OSV](https://ossf.github.io/osv-schema/) model.
- **[Grype](https://github.com/anchore/grype)** — vulnerability matcher; often paired with **[Syft](https://github.com/anchore/syft)** (SBOM generation).
- **[Trivy](https://github.com/aquasecurity/trivy)** — broad security scanner (containers, IaC, language deps, etc.).
- **[OWASP Dependency-Check](https://github.com/jeremylong/DependencyCheck)** — dependency analysis with multiple advisory sources.
- **Ecosystem-native CLIs (for cross-language comparisons)**  
  - **[npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit)** (Node.js)  
  - **[cargo audit](https://github.com/RustSec/cargo-audit)** (Rust)

## Initialization
```
go mod init github.com/Wapiti08/gosecure
go install github.com/spf13/cobra-cli@latest
go mod tidy
```