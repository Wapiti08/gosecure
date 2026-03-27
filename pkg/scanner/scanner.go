package scanner

/*
define shared types/interfaces, like Scanner, Vulnerability, helper functions

*/

import (
	"context"
	"fmt"
)

// define the vulnerablity struct
type Vulnerability struct {
	ID 		string  `json:"id"`  // CVE-2023-1234
	Package string  `json:"package"`  //golang.org/x/text
	Version string  `json:"version"`  //v0.3.0
	Severity string `json:"severity"` // High, Medium, Low
	Summary string  `json:"summary"` // vulnerability summary
	Fixed   []string `json:"fixed"`   // list of fixed versions
}

type VulnChecker interface {
	Check(ctx context.Context, module, version string) ([]Vulnerability, error)
}

// Scanner interface defines the method to scan a project for vulnerabilities
type Scanner interface {
	// scan defined path and return a list of vulnerabilities --- add context for potential goroutine exit
	Scan(ctx context.Context, path string) ([]Vulnerability, error)

	// check whether the file is supported by the scanner
	Support(path string) bool
}

// ScanResult
type ScanResult struct {
	FilePath    string     `json:"file_path"`
	Vulnerability []Vulnerability `json:"vulnerabilities"`
	Error     error     `json:"error,omitempty"`
}

// user-friendly output format
func (v Vulnerability) String() string {
	return fmt.Sprintf("[%s] %s@%s - %s", v.Severity, v.Package, v.Version, v.ID)
}

// count vulnerabilities by severity
func CountBySeverity(vulns []Vulnerability) map[string]int {
	counts := make(map[string]int)
	for _, v := range vulns {
		counts[v.Severity]++
	}
	return counts
}

func ScanProject(ctx, root string, scanners []Scanner) ([]Vulnerability, error) {

}