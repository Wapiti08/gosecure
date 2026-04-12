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

**Planned for dependency diff & risk (feature line 5)** — add when you implement them, to keep scanning vs. scoring separated:

- `pkg/diff/`: compare two dependency snapshots (e.g. two lockfiles or two resolved graphs); output added/removed/changed packages.

- `pkg/risk/`: pure scoring and policy (package age, popularity proxies, maintainer signals, post-install script flags); consumed by CLI or diff reports.

## Initialization
```
go mod init github.com/Wapiti08/gosecure
go install github.com/spf13/cobra-cli@latest
go mod tidy
```