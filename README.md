# gosecure
A golang-based high-performance dependency scanning tool


## Core Features
- extreme-speed scanning (compared with govulncheck)
- golang-based, extensible
- deep transitive dependency scanning (up to 3 levels), catching vulnerabilities hidden in nested deps (e.g. axios → follow-redirects)
- visualized dependency graph
- plugin-support, multi-language support

## Structure

- cmd/gosecure/: CLI entrypoint (wires flags -> scanner execution)

- pkg/scanner/: scanning library

    - scanner.go: interfaces + shared data structures

    - gomod.go: implementation for Go module scanning 

    - scanner_test.go: uni tests

- pkg/vuln/: implementations of VulnChecker (OSV, NVD, caching, etc.)

## Initialization
```
go mod init github.com/Wapiti08/gosecure
go install github.com/spf13/cobra-cli@latest
```